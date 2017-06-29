package com.mesosphere.sdk.offer.evaluate;

import com.mesosphere.sdk.dcos.CertificateAuthorityClient;
import com.mesosphere.sdk.dcos.DcosConstants;
import com.mesosphere.sdk.dcos.SecretsClient;
import com.mesosphere.sdk.dcos.auth.CachedTokenProvider;
import com.mesosphere.sdk.dcos.auth.ServiceAccountIAMTokenProvider;
import com.mesosphere.sdk.dcos.auth.TokenProvider;
import com.mesosphere.sdk.dcos.ca.DefaultCAClient;
import com.mesosphere.sdk.dcos.ca.PEMHelper;
import com.mesosphere.sdk.dcos.http.DcosHttpClientBuilder;
import com.mesosphere.sdk.dcos.http.URLHelper;
import com.mesosphere.sdk.dcos.secrets.AlreadyExistsException;
import com.mesosphere.sdk.dcos.secrets.DefaultSecretsClient;
import com.mesosphere.sdk.dcos.secrets.Secret;
import com.mesosphere.sdk.dcos.secrets.SecretsException;
import com.mesosphere.sdk.offer.MesosResourcePool;
import com.mesosphere.sdk.offer.evaluate.security.CertificateNamesGenerator;
import com.mesosphere.sdk.offer.evaluate.security.SecretNameGenerator;
import com.mesosphere.sdk.scheduler.SchedulerFlags;
import com.mesosphere.sdk.specification.TransportEncryptionSpec;
import org.apache.http.client.fluent.Executor;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.mesos.Protos;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.stream.Collectors;

/**
 * A {@link TLSEvaluationStage} is responsible for provisioning X.509 certificates, converting them to
 * PEM and KeyStore formats and injecting them to the container as a secret.
 */
public class TLSEvaluationStage implements OfferEvaluationStage {

    private static final Logger LOGGER = LoggerFactory.getLogger(TLSEvaluationStage.class);

    private String serviceName;
    private String taskName;
    private CertificateAuthorityClient certificateAuthorityClient;
    private SecretsClient secretsClient;
    private KeyPairGenerator keyPairGenerator;

    public TLSEvaluationStage(
            String serviceName,
            String taskName,
            CertificateAuthorityClient certificateAuthorityClient,
            SecretsClient secretsClient,
            KeyPairGenerator keyPairGenerator) {
        this.serviceName = serviceName;
        this.taskName = taskName;
        this.certificateAuthorityClient = certificateAuthorityClient;
        this.secretsClient = secretsClient;
        this.keyPairGenerator = keyPairGenerator;
    }

    public static TLSEvaluationStage fromEnvironmentForService(
            String serviceName,
            String taskName) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {

        SchedulerFlags flags = SchedulerFlags.fromEnv();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        PemReader pemReader = new PemReader(new StringReader(flags.getServiceAccountPrivateKeyPEM()));
        PrivateKey privateKey = keyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(pemReader.readPemObject().getContent()));

        ServiceAccountIAMTokenProvider serviceAccountIAMTokenProvider = new ServiceAccountIAMTokenProvider.Builder()
                .setIamUrl(URLHelper.fromUnchecked(DcosConstants.IAM_AUTH_URL))
                .setUid(flags.getServiceAccountUid())
                .setPrivateKey((RSAPrivateKey) privateKey)
                .build();
        TokenProvider tokenProvider = new CachedTokenProvider(serviceAccountIAMTokenProvider);

        Executor executor = Executor.newInstance(
                new DcosHttpClientBuilder()
                        .setTokenProvider(tokenProvider)
                        .setRedirectStrategy(new LaxRedirectStrategy())
                        .build());

        CertificateAuthorityClient certificateAuthorityClient = new DefaultCAClient(executor);
        SecretsClient secretsClient = new DefaultSecretsClient(executor);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        return new TLSEvaluationStage(
                serviceName, taskName, certificateAuthorityClient, secretsClient, keyPairGenerator);

    }

    @Override
    public EvaluationOutcome evaluate(MesosResourcePool mesosResourcePool, PodInfoBuilder podInfoBuilder) {

        String filenameInContainer = podInfoBuilder
                .getPodInstance()
                .getPod()
                .getTransportEncryption()
                .get()
                .getName();

        SecretNameGenerator secretNameGenerator = new SecretNameGenerator(
                serviceName,
                taskName,
                filenameInContainer);

        // Generate new private key and encode it to PEM
        // Generate new CSR, sign it, encode certificate to PEM
        try {
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            X509Certificate certificate = certificateAuthorityClient.sign(generateCSR(keyPair));
            ArrayList<X509Certificate> certificateChain = (ArrayList<X509Certificate>)
                    certificateAuthorityClient.chainWithRootCert(certificate);

            ArrayList<X509Certificate> endEntityCertificateWithChain = new ArrayList<>();
            // Add end-entity certificate
            endEntityCertificateWithChain.add(certificate);
            // Add all possible certificates in the chain
            if (certificateChain.size() > 1) {
                endEntityCertificateWithChain.addAll(certificateChain.subList(0, certificateChain.size() - 1));
            }
            // Convert to pem and join to a single string
            String certPEM = endEntityCertificateWithChain.stream()
                    .map(cert -> {
                        try {
                            return PEMHelper.toPEM(cert);
                        } catch (IOException e) {
                            throw new UncheckedIOException(e);
                        }
                    })
                    .collect(Collectors.joining("\n"));

            String privateKeyPEM = PEMHelper.toPEM(keyPair.getPrivate());
            String rootCACertPEM = PEMHelper.toPEM(
                    certificateChain.get(certificateChain.size() - 1));

            KeyStore keyStore = createEmptyKeyStore();
            keyStore.setCertificateEntry(filenameInContainer, certificate);

            certificateChain.add(0, certificate);
            Certificate[] keyStoreChain = new Certificate[]{};
            certificateChain.toArray(keyStoreChain);

            keyStore.setKeyEntry(filenameInContainer, keyPair.getPrivate().getEncoded(), keyStoreChain);

            KeyStore trustStore = createEmptyKeyStore();
            trustStore.setCertificateEntry("dcos-root", certificateChain.get(certificateChain.size() - 1));

            storeSecrets(secretNameGenerator, certPEM, privateKeyPEM, rootCACertPEM, keyStore, trustStore);
        } catch (Exception e) {
            LOGGER.error("Failed to get certificate", e);
            return EvaluationOutcome.fail(
                    this, "Failed because of exception: %s", e);
        }

        Collection<Protos.Volume> volumes = getExecutorInfoSecretVolumes(podInfoBuilder, secretNameGenerator);

        // Share keys to the container
        Optional<Protos.ExecutorInfo.Builder> executorBuilder = podInfoBuilder.getExecutorBuilder();
        Protos.TaskInfo.Builder taskBuilder = podInfoBuilder.getTaskBuilder(taskName);
        if (executorBuilder.isPresent()) {
            executorBuilder.get()
                    .getContainerBuilder()
                    .setType(Protos.ContainerInfo.Type.MESOS)
                    .addAllVolumes(volumes);
            taskBuilder.setExecutor(executorBuilder.get());
        }

        return EvaluationOutcome.pass(
                this, null, "TLS certificate created and added to the pod");

    }

    private Collection<Protos.Volume> getExecutorInfoSecretVolumes(
            PodInfoBuilder podInfoBuilder, SecretNameGenerator secretNameGenerator) {
        HashMap<String, String> tlsSecrets = new HashMap<>();

        TransportEncryptionSpec.Type transportEncryptionType = podInfoBuilder
                .getPodInstance()
                .getPod()
                .getTransportEncryption()
                .get()
                .getType();

        if (transportEncryptionType.equals(TransportEncryptionSpec.Type.TLS)) {
            tlsSecrets.put(secretNameGenerator.getCertificatePath(), secretNameGenerator.getCertificateMountPath());
            tlsSecrets.put(secretNameGenerator.getPrivateKeyPath(), secretNameGenerator.getPrivateKeyMountPath());
            tlsSecrets.put(secretNameGenerator.getRootCACertPath(), secretNameGenerator.getRootCACertMountPath());
        } else if (transportEncryptionType.equals(TransportEncryptionSpec.Type.KEYSTORE)) {
            tlsSecrets.put(secretNameGenerator.getKeyStorePath(), secretNameGenerator.getKeyStoreMountPath());
            tlsSecrets.put(secretNameGenerator.getTrustStorePath(), secretNameGenerator.getTrustStoreMountPath());
        }

        Collection<Protos.Volume> volumes = new ArrayList<>();

        tlsSecrets.entrySet().forEach(tlsSecretEntry ->
                volumes.add(Protos.Volume.newBuilder()
                        .setSource(Protos.Volume.Source.newBuilder()
                                .setType(Protos.Volume.Source.Type.SECRET)
                                .setSecret(getReferenceSecret(tlsSecretEntry.getKey()))
                                .build())
                        .setContainerPath(tlsSecretEntry.getValue())
                        .setMode(Protos.Volume.Mode.RO)
                        .build())
        );

        return volumes;
    }

    private static Protos.Secret getReferenceSecret(String secretPath) {
        return Protos.Secret.newBuilder()
                .setType(Protos.Secret.Type.REFERENCE)
                .setReference(Protos.Secret.Reference.newBuilder().setName(secretPath))
                .build();
    }

    private void storeSecrets(
            SecretNameGenerator secretNameGenerator,
            String certPEM,
            String privateKeyPEM,
            String rootCACertPEM,
            KeyStore keyStore,
            KeyStore trustStore) throws IOException, SecretsException, CertificateException,
            NoSuchAlgorithmException, KeyStoreException {

        // TODO(mh): How should we handle partially existing secrets?
        try {
            LOGGER.info(String.format("Creating new secret: %s", secretNameGenerator.getCertificatePath()));
            secretsClient.create(
                    secretNameGenerator.getCertificatePath(),
                    buildSecret(certPEM, "PEM encoded certificate"));

            LOGGER.info(String.format("Creating new secret: %s", secretNameGenerator.getPrivateKeyPath()));
            secretsClient.create(
                    secretNameGenerator.getPrivateKeyPath(),
                    buildSecret(privateKeyPEM, "PEM encoded private key"));

            LOGGER.info(String.format("Creating new secret: %s", secretNameGenerator.getRootCACertPath()));
            secretsClient.create(
                    secretNameGenerator.getRootCACertPath(),
                    buildSecret(rootCACertPEM, "PEM encoded root CA certificate"));

            ByteArrayOutputStream keyStoreOs = new ByteArrayOutputStream();
            keyStore.store(keyStoreOs, new char[0]);
            String encodedKeyStore = Base64.getEncoder().encodeToString(keyStoreOs.toByteArray());
            LOGGER.info(String.format("Creating new secret: %s", secretNameGenerator.getKeyStorePath()));
            secretsClient.create(
                    secretNameGenerator.getKeyStorePath(),
                    buildSecret(encodedKeyStore, "Base64 encoded java keystore"));

            ByteArrayOutputStream trustStoreOs = new ByteArrayOutputStream();
            trustStore.store(trustStoreOs, new char[0]);
            String encodedTrustStore = Base64.getEncoder().encodeToString(keyStoreOs.toByteArray());
            LOGGER.info(String.format("Creating new secret: %s", secretNameGenerator.getTrustStorePath()));
            secretsClient.create(
                    secretNameGenerator.getTrustStorePath(),
                    buildSecret(encodedTrustStore, "Base64 encoded java trust store"));
        } catch (AlreadyExistsException e) {
            LOGGER.info("Secret already exists", e);
        }
    }

    private Secret buildSecret(String value, String description) {
        return new Secret.Builder()
                .value(value)
                .author(serviceName)
                .description(description)
                .build();
    }

    private KeyStore createEmptyKeyStore()
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, new char[0]);
        return keyStore;
    }

    private byte[] generateCSR(
            KeyPair keyPair) throws IOException, OperatorCreationException {

        CertificateNamesGenerator certificateNamesGenerator = new CertificateNamesGenerator(
                serviceName, taskName);

        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();

        extensionsGenerator.addExtension(
                Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));

        extensionsGenerator.addExtension(
                Extension.extendedKeyUsage,
                true,
                new ExtendedKeyUsage(
                        new KeyPurposeId[] {
                                KeyPurposeId.id_kp_clientAuth,
                                KeyPurposeId.id_kp_serverAuth
                        }
                ));

        extensionsGenerator.addExtension(
                Extension.subjectAlternativeName, true, certificateNamesGenerator.getSANs());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(keyPair.getPrivate());

        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(
                certificateNamesGenerator.getSubject(), keyPair.getPublic())
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
        PKCS10CertificationRequest csr = csrBuilder.build(signer);

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        PemWriter writer = new PemWriter(new OutputStreamWriter(os, Charset.forName("UTF-8")));
        writer.writeObject(new JcaMiscPEMGenerator(csr));
        writer.flush();

        return os.toByteArray();
    }
}

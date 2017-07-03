package com.mesosphere.sdk.offer.evaluate;

import com.mesosphere.sdk.dcos.CertificateAuthorityClient;
import com.mesosphere.sdk.dcos.DcosConstants;
import com.mesosphere.sdk.dcos.SecretsClient;
import com.mesosphere.sdk.dcos.auth.CachedTokenProvider;
import com.mesosphere.sdk.dcos.auth.ServiceAccountIAMTokenProvider;
import com.mesosphere.sdk.dcos.auth.TokenProvider;
import com.mesosphere.sdk.dcos.ca.DefaultCAClient;
import com.mesosphere.sdk.dcos.http.DcosHttpClientBuilder;
import com.mesosphere.sdk.dcos.http.URLHelper;
import com.mesosphere.sdk.dcos.secrets.DefaultSecretsClient;
import com.mesosphere.sdk.offer.MesosResourcePool;
import com.mesosphere.sdk.offer.evaluate.security.SecretNameGenerator;
import com.mesosphere.sdk.offer.evaluate.security.TLSArtifacts;
import com.mesosphere.sdk.offer.evaluate.security.TLSArtifactsGenerator;
import com.mesosphere.sdk.offer.evaluate.security.TLSArtifactsPersister;
import com.mesosphere.sdk.scheduler.SchedulerFlags;
import com.mesosphere.sdk.specification.TaskSpec;
import com.mesosphere.sdk.specification.TransportEncryptionSpec;
import org.apache.http.client.fluent.Executor;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.mesos.Protos;
import org.bouncycastle.util.io.pem.PemReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Optional;

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
        TaskSpec taskSpec = findTaskSpec(podInfoBuilder);

        for (TransportEncryptionSpec transportEncryptionSpec : taskSpec.getTransportEncryption()) {
            String transportEncryptionName = transportEncryptionSpec.getName();

            SecretNameGenerator secretNameGenerator = new SecretNameGenerator(
                    serviceName,
                    taskName,
                    transportEncryptionName);

            TLSArtifactsPersister persister = new TLSArtifactsPersister(secretsClient, serviceName);

            try {
                if (!persister.isArtifactComplete(secretNameGenerator)) {
                    persister.cleanUpSecrets(secretNameGenerator);

                    TLSArtifacts tlsArtifacts = new TLSArtifactsGenerator(
                            serviceName, taskName, keyPairGenerator, certificateAuthorityClient)
                            .provision();
                    persister.persist(secretNameGenerator, tlsArtifacts);
                } else {
                    LOGGER.info(
                            String.format(
                                    "Task '%s' has already all secrets for '%s' TLS config",
                                    taskName, transportEncryptionName));
                }
            } catch (Exception e) {
                LOGGER.error("Failed to get certificate ", taskName, e);
                return EvaluationOutcome.fail(
                        this, "Failed to store TLS artifacts for task %s because of exception: %s", taskName, e);
            }

            Collection<Protos.Volume> volumes = getExecutorInfoSecretVolumes(
                    transportEncryptionSpec, secretNameGenerator);

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
        }

        return EvaluationOutcome.pass(
                this, null, "TLS certificate created and added to the task");

    }

    private TaskSpec findTaskSpec(PodInfoBuilder podInfoBuilder) {
        return podInfoBuilder
                .getPodInstance()
                .getPod()
                .getTasks()
                .stream()
                .filter(task -> task.getName().equals(taskName))
                .findFirst()
                .get();

    }

    private Collection<Protos.Volume> getExecutorInfoSecretVolumes(
            TransportEncryptionSpec transportEncryptionSpec, SecretNameGenerator secretNameGenerator) {
        HashMap<String, String> tlsSecrets = new HashMap<>();

        if (transportEncryptionSpec.getType().equals(TransportEncryptionSpec.Type.TLS)) {
            tlsSecrets.put(secretNameGenerator.getCertificatePath(), secretNameGenerator.getCertificateMountPath());
            tlsSecrets.put(secretNameGenerator.getPrivateKeyPath(), secretNameGenerator.getPrivateKeyMountPath());
            tlsSecrets.put(secretNameGenerator.getRootCACertPath(), secretNameGenerator.getRootCACertMountPath());
        } else if (transportEncryptionSpec.getType().equals(TransportEncryptionSpec.Type.KEYSTORE)) {
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

}

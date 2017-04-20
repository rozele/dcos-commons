package com.mesosphere.sdk.offer.evaluate;

import com.mesosphere.sdk.offer.OfferRecommendation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

/**
 * The outcome of invoking an {@link OfferEvaluationStage}. Describes whether the evaluation passed or failed, and the
 * reason(s) why. Supports a nested tree of outcomes which describe any sub-evaluations which may have been performed
 * within the {@link OfferEvaluationStage}.
 */
public class EvaluationOutcome {

    /**
     * The outcome value.
     */
    private enum Type {
        PASS,
        FAIL
    }

    private final Type type;
    private final String source;
    private final String reason;

    private Collection<EvaluationOutcome> children;
    private Collection<OfferRecommendation> offerRecommendations;

    /**
     * Returns a new passing outcome object with the provided descriptive reason.
     *
     * @param source the object which produced this outcome, whose class name will be labeled as the origin
     * @param reasonFormat {@link String#format(String, Object...)} compatible format string describing the pass reason
     * @param reasonArgs format arguments, if any, to apply against {@code reasonFormat}
     */
    public static EvaluationOutcome pass(Object source, String reasonFormat, Object... reasonArgs) {
        return create(true, source, reasonFormat, reasonArgs);
    }

    /**
     * Returns a new failing outcome object with the provided descriptive reason.
     *
     * @param source the object which produced this outcome, whose class name will be labeled as the origin
     * @param reasonFormat {@link String#format(String, Object...)} compatible format string describing the fail reason
     * @param reasonArgs format arguments, if any, to apply against {@code reasonFormat}
     */
    public static EvaluationOutcome fail(Object source, String reasonFormat, Object... reasonArgs) {
        return create(false, source, reasonFormat, reasonArgs);
    }

    /**
     * Returns a new outcome object with the provided outcome type, offer recommendation, descriptive reason, and child
     * outcomes.
     */
    public static EvaluationOutcome create(
            boolean isPassing,
            Object source,
            String reasonFormat,
            Object... reasonArgs) {
        return new EvaluationOutcome(
                isPassing ? Type.PASS : Type.FAIL, source, reasonFormat, reasonArgs);
    }

    private EvaluationOutcome(
            Type type,
            Object source,
            String reasonFormat,
            Object... reasonArgs) {
        this.type = type;
        this.source = source.getClass().getSimpleName();
        this.reason = String.format(reasonFormat, reasonArgs);

        this.children = Collections.emptyList();
        this.offerRecommendations = Collections.emptyList();
    }

    /**
     * Shortcut to calling {@link #setOfferRecommendations(Collection)} with a single recommendation. Any previous
     * recommendations are removed.
     *
     * @return {@code this}
     */
    public EvaluationOutcome setOfferRecommendation(OfferRecommendation offerRecommendation) {
        return setOfferRecommendations(Arrays.asList(offerRecommendation));
    }

    /**
     * Assigns the provided list of offer recommendations to this outcome. Any previous recommendations are removed.
     *
     * @return {@code this}
     */
    public EvaluationOutcome setOfferRecommendations(Collection<OfferRecommendation> offerRecommendations) {
        this.offerRecommendations = offerRecommendations;
        return this;
    }

    /**
     * Assigns the provided list of child outcomes to this outcome. Any previous children are removed.
     *
     * @return {@code this}
     */
    public EvaluationOutcome setChildren(Collection<EvaluationOutcome> children) {
        this.children = children;
        return this;
    }

    /**
     * Returns whether this outcome was passing ({@code true}) or failing ({@code false}).
     */
    public boolean isPassing() {
        return type == Type.PASS;
    }

    /**
     * Returns the name of the object which produced this response.
     */
    public String getSource() {
        return source;
    }

    /**
     * Returns the reason that this response is passing or failing.
     */
    public String getReason() {
        return reason;
    }

    /**
     * Returns any nested outcomes which resulted in this decision.
     */
    public Collection<EvaluationOutcome> getChildren() {
        return children;
    }

    /**
     * Returns any offer recommendations which should be applied when accepting the offer, including those from child
     * outcomes.
     */
    public Collection<OfferRecommendation> getOfferRecommendations() {
        Collection<OfferRecommendation> recommendations = new ArrayList<>();
        recommendations.addAll(offerRecommendations);
        for (EvaluationOutcome outcome : getChildren()) {
            recommendations.addAll(outcome.getOfferRecommendations());
        }
        return recommendations;
    }

    @Override
    public String toString() {
        return String.format("%s(%s): %s", isPassing() ? "PASS" : "FAIL", getSource(), getReason());
    }
}

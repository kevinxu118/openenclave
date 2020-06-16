#include <my_plugin_verifier.h>

/* Plugin implementation functions here. */
static oe_result_t my_plugin_on_register(
    oe_verifier_t* plugin_context,
    const void* config_data,
    size_t config_data_size)
{
    OE_UNUSED(plugin_context);
    OE_UNUSED(config_data);
    OE_UNUSED(config_data_size);

    // Nothing to do
    return OE_OK;
}

static oe_result_t my_plugin_on_unregister(oe_verifier_t* plugin_context)
{
    OE_UNUSED(plugin_context);

    // Nothing to do
    return OE_OK;
}

static oe_result_t my_plugin_verify_evidence(
    oe_verifier_t* plugin_context,
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* endorsements_buffer,
    size_t endorsements_buffer_size,
    const oe_policy_t* polices,
    size_t policies_size,
    oe_claim_t** claims,
    size_t* claims_length)
{
    OE_UNUSED(plugin_context);

    /*
     * Pseudocode description instead of actual C code:
     *
     * Call oe_verify_report with all the input parameters and get the
     * oe_identity_t back. Look for the custom claims in the evidence header and
     * extract them if found. Verify the hash of custom claims == report data
     * field in evidence report. Convert oe_identity_t to the claims format.
     *
     * Note: Since the verifier can run outside the SGX enclave, it can be
     * running on a machine with different endianness. Consequently, the
     * verification code needs to understand the endianness of the multibyte
     * numbers in the evidence and endorsements and intelligently convert them
     * to the verifier's native architecture.
     */

    /*
     * Use endorsements and policies as needed for your plugin.
     * Demonstrated as unused here.
     */
    OE_UNUSED(endorsements_buffer);
    OE_UNUSED(endorsements_buffer_size);
    OE_UNUSED(policies);
    OE_UNUSED(policies_size);

    oe_result_t result = OE_OK;
    oe_report_t parsed_report = {0};

    result =
        oe_verify_report(evidence_buffer, evidence_buffer_size, &parsed_report);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_verify_report failed (%s).\n", oe_result_str(result));
        goto exit;
    }

    TRACE_ENCLAVE("oe_verify_report succeeded\n");

    return OE_OK;
}

static oe_result_t my_plugin_free_claims_list(
    oe_verifier_t* plugin_context,
    oe_claim_t* claims,
    size_t claims_length)
{
    OE_UNUSED(plugin_context);
    for (size_t i = 0; i < claims_length; i++)
    {
        free(claims[i].name);
        free(claims[i].value);
    }
    return OE_OK;
}

/* Setting up the plugin struct. */
oe_verifier_t my_plugin = {.base =
                               {
                                   .format_id = MY_PLUGIN_UUID,
                                   .on_register = my_plugin_on_register,
                                   .on_unregister = my_plugin_on_unregister,
                               },
                           .verify_evidence = my_plugin_verify_evidence,
                           .free_claims_list = my_plugin_free_claims_list};

/* Implement helper initialization function. */
oe_verifier_t* my_plugin_attester()
{
    return &my_plugin;
}
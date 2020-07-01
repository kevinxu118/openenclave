#include "my_plugin_verifier.h"

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

/* Borrowed from SGX implementation. */
static oe_result_t _add_claim(
    oe_claim_t* claim,
    void* name,
    size_t name_size,
    void* value,
    size_t value_size)
{
    if (*((uint8_t*)name + name_size - 1) != '\0')
        return OE_CONSTRAINT_FAILED;

    claim->name = (char*)oe_malloc(name_size);
    if (claim->name == NULL)
        return OE_OUT_OF_MEMORY;
    memcpy(claim->name, name, name_size);

    claim->value = (uint8_t*)oe_malloc(value_size);
    if (claim->value == NULL)
    {
        oe_free(claim->name);
        claim->name = NULL;
        return OE_OUT_OF_MEMORY;
    }
    memcpy(claim->value, value, value_size);
    claim->value_size = value_size;

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
    oe_claim_t** claims_out,
    size_t* claims_length)
{
    OE_UNUSED(plugin_context);

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

    if (!claims || !claims_length)
        OE_RAISE(OE_INVALID_PARAMETER);

    result =
        oe_verify_report(evidence_buffer, evidence_buffer_size, &parsed_report);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_verify_report failed (%s).\n", oe_result_str(result));
        goto exit;
    }

    TRACE_ENCLAVE("oe_verify_report succeeded\n");

    oe_claim_t* claims = (oe_claim_t*)oe_malloc(
        8 * sizeof(oe_claim_t));

    if (claims == NULL)
        return OE_OUT_OF_MEMORY;

    size_t claims_index = 0;

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_ID_VERSION,
        sizeof(OE_CLAIM_ID_VERSION),
        &(parsed_report.identity.id_version),
        sizeof(parsed_report.identity.id_version)));

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_SECURITY_VERSION,
        sizeof(OE_CLAIM_SECURITY_VERSION),
        &(parsed_report.identity.security_version),
        sizeof(parsed_report.identity.security_version)));

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_ATTRIBUTES,
        sizeof(OE_CLAIM_ATTRIBUTES),
        &(parsed_report.identity.attributes),
        sizeof(parsed_report.identity.attributes)));

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_UNIQUE_ID,
        sizeof(OE_CLAIM_UNIQUE_ID),
        (void*)&(parsed_report.identity.unique_id),
        OE_UNIQUE_ID_SIZE));

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_SIGNER_ID,
        sizeof(OE_CLAIM_SIGNER_ID),
        (void*)&(parsed_report.identity.signer_id),
        OE_SIGNER_ID_SIZE));

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_PRODUCT_ID,
        sizeof(OE_CLAIM_PRODUCT_ID),
        (void*)&(parsed_report.identity.product_id),
        OE_PRODUCT_ID_SIZE));

    // Demonstrating a custom claim.
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        "report_data",
        sizeof("report_data"),
        &(parsed_report.report_data),
        sizeof(parsed_report.report_data)));

    *claims_out = claims;
    *claims_size_out = 7;

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

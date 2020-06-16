#include <my_plugin_attester.h>

/* Plugin implementation functions here. */
static oe_result_t my_plugin_on_register(
    oe_attester_t* context,
    const void* config_data,
    size_t config_data_size)
{
    OE_UNUSED(context);
    OE_UNUSED(config_data);
    OE_UNUSED(config_data_size);

    // Nothing to do
    return OE_OK;
}

static oe_result_t my_plugin_on_unregister(oe_attester_t* plugin_context)
{
    OE_UNUSED(plugin_context);

    // Nothing to do
    return OE_OK;
}

static oe_result_t my_plugin_get_evidence(
    oe_attester_t* plugin_context,
    uint32_t flags,
    const oe_claim_t* custom_claims,
    size_t custom_claims_length,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size,
    uint8_t** endorsements_buffer,
    size_t* endorsements_buffer_size)
{
    OE_UNUSED(plugin_context);

    /*
     * Use custom claims and endorsements as needed for your plugin.
     * Demonstrated as unused here.
     */
    OE_UNUSED(custom_claims);
    OE_UNUSED(custom_claims_length);
    OE_UNUSED(endorsements_buffer);
    OE_UNUSED(endorsements_buffer_size);

    bool ret = false;
    oe_result_t result = OE_OK;
    uint8_t* temp_buf = NULL;

    if (flags == OE_EVIDENCE_FLAGS_REMOTE_ATTESTATION)
    {
        // TODO: Remote attestation.
        return OE_OK;
    }

    // Default is local attestation.

    // Grab the necessary data from the evidence.
    struct my_plugin_attester_opt_params_t* opt_casted =
        (struct my_plugin_attester_opt_params_t*)opt_params;

    result = oe_get_report(
        0, // get a local report
        opt_casted->sha256,
        sizeof(opt_casted->sha256),
        opt_casted->target_info_buffer,
        opt_casted->target_info_size,
        &temp_buf,
        evidence_buffer_size);

    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_get_report failed.");
        return false;
    }
    *evidence_buffer = temp_buf;
    ret = true;
    TRACE_ENCLAVE("generate_local_report succeeded.");

    return OE_OK;
}

static oe_result_t my_plugin_free_evidence(
    oe_attester_t* plugin_context,
    uint8_t* evidence_buffer)
{
    OE_UNUSED(plugin_context);
    free(evidence_buffer);
    return OE_OK;
}

static oe_result_t my_plugin_free_endorsements(
    oe_attester_t* plugin_context,
    uint8_t* endorsements_buffer)
{
    OE_UNUSED(plugin_context);
    free(endorsements_buffer);
    return OE_OK;
}

/* Setting up the plugin struct. */
oe_attester_t my_plugin = {.base =
                               {
                                   .format_id = MY_PLUGIN_UUID,
                                   .on_register = my_plugin_on_register,
                                   .on_unregister = my_plugin_on_unregister,
                               },
                           .get_evidence = my_plugin_get_evidence,
                           .free_evidence = my_plugin_free_evidence,
                           .free_endorsements = my_plugin_free_endorsements};

/* Implement helper initialization function. */
oe_attester_t* my_plugin_attester()
{
    return &my_plugin;
}
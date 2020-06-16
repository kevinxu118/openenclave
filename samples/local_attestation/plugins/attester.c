#include <my_plugin_attester.h>

/* Register plugin. Send the config data if necessary. */
struct my_plugin_attester_config_data_t config = NULL;
size_t config_size = sizeof(config);
oe_register_attester(my_plugin_attester(), NULL, config_size);

/* Get evidence. */
oe_get_evidence(
    MY_PLUGIN_UUID,
    0,
    claims,
    claims_size,
    &params,
    params_size,
    &evidence,
    &evidence_size,
    &endorsements,
    &endorsements_size);

/* Send the evidence to the verifier. Protocol is up to enclave and verifier. */
send(VERIFIER_SOCKET_FD, evidence, evidence_size, 0);
send(VERIFIER_SOCKET_FD, endorsements, endorsements_size, 0);

/* Free data and unregister plugin. */
oe_free_evidence(evidence);
oe_free_endorsements(endorsements);
oe_unregister_attester(my_plugin_attester());
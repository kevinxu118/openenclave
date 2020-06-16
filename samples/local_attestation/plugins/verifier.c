#include <my_plugin_verifier.h>

/* Register plugin. Send the config data if necessary. */
struct my_plugin_verifier_config_data_t config = NULL;
size_t config_size = sizeof(config);
oe_register_verifier(my_plugin_verifier(), NULL, config_size);

/* Receive evidence and endorsement buffer from enclave. */
recv(ENCLAVE_SOCKET_FD, evidence, evidence_size, 0);
recv(ENCLAVE_SOCKET_FD, endorsements, endorsements_size, 0);

/* Set polices if desired. */
oe_datetime_t time = {0};
oe_policy_t policy = {.type = OE_POLICY_ENDORSEMENTS_TIME,
                      .policy = &time,
                      .policy_size = sizeof(time);
}
;

/* Verify evidence. Can check the claims if desired. */
oe_verify_evidence(
    evidence,
    evidence_size,
    endorsements,
    endorsements_size,
    &policy,
    1,
    &claims,
    &claims_size);

/* Free data and unregister plugin. */
oe_free_claims_list(claims, claims_size);
oe_unregister_verifier(my_plugin_verifier());
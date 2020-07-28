// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "attestation.h"
#include <string.h>
#include "log.h"
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/verifier.h>

// SGX local attestation UUID.
static oe_uuid_t sgx_local_uuid = {OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};
oe_uuid_t selected_format;

Attestation::Attestation(Crypto* crypto, uint8_t* enclave_mrsigner)
{
    m_crypto = crypto;
    m_enclave_mrsigner = enclave_mrsigner;
}

/**
 * Generate evidence for the given data.
 */
bool Attestation::generate_local_attestation_evidence(
    uint8_t* target_info_buffer,
    size_t target_info_size,
    const uint8_t* data,
    const size_t data_size,
    uint8_t** evidence_buf,
    size_t* local_evidence_buf_size)
{
    bool ret = false;
    uint8_t sha256[32];
    oe_result_t result = OE_OK;    
    oe_result_t attester_result = OE_OK;
    oe_result_t attester_format_result = OE_OK;

    if (m_crypto->Sha256(data, data_size, sha256) != 0)
    {
        goto exit;
    }

    // Initialize attester and use the SGX plugin.
    attester_result = oe_attester_initialize();
    if (attester_result != OE_OK)
    {
        TRACE_ENCLAVE("oe_attester_initialize failed.");
        goto exit;
    }

    
    // // Select the attestation format.
    // attester_format_result = oe_attester_select_format(&sgx_local_uuid, 1, &selected_format);
    // if (attester_format_result != OE_OK)
    // {
    //     TRACE_ENCLAVE("oe_attester_select_format failed.");
    //     goto exit;
    // }

    // Generate evidence based on the format selected by the attester.
    result = oe_get_evidence(&sgx_local_uuid, NULL, NULL, 0, target_info_buffer, target_info_size, evidence_buf, local_evidence_buf_size, NULL, 0);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_get_evidence failed.");
        goto exit;
    }

    ret = true;
    TRACE_ENCLAVE("generate_local_attestation_evidence succeeded.");
exit:
    return ret;
}

/**
 * Attest the given evidence and accompanying data. It consists of the
 * following three steps:
 *
 * 1) The local evidence is first attested using the oe_verify_evidence API. This
 * ensures the authenticity of the enclave that generated the evidence.
 * 2) Next, to establish trust of the enclave that generated the evidence,
 * the mrsigner, product_id, isvsvn values are checked to  see if they are
 * predefined trusted values.
 */
bool Attestation::attest_local_evidence(
    const uint8_t* local_evidence,
    size_t evidence_size,
    const uint8_t* data,
    size_t data_size)
{
    bool ret = false;
    uint8_t sha256[32];
    oe_result_t result = OE_OK;
    oe_result_t verifier_result = OE_OK;
    oe_claim_t* claims = NULL;
    size_t claims_length = 0;

    // While attesting, the evidence being attested must not be tampered
    // with. Ensure that it has been copied over to the enclave.
    if (!oe_is_within_enclave(local_evidence, evidence_size))
    {
        TRACE_ENCLAVE("Cannot attest evidence in host memory. Unsafe.");
        goto exit;
    }

    TRACE_ENCLAVE("evidence_size = %ld", evidence_size);

    verifier_result = oe_verifier_initialize();
    if (verifier_result != OE_OK)
    {
        TRACE_ENCLAVE("oe_verifier_initialize failed.");
        goto exit;
    }

    // 1)  Validate the evidence's trustworthiness
    // Verify the evidence to ensure its authenticity.
    result = oe_verify_evidence(&sgx_local_uuid, local_evidence, evidence_size, NULL, 0, NULL, 0, &claims, &claims_length);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_verify_evidence failed (%s).\n", oe_result_str(result));
        goto exit;
    }

    TRACE_ENCLAVE("oe_verify_evidence succeeded\n");

    // Iterate through list of claims.
    for (size_t i = 0; i < claims_length; i++) 
    {
        if (strcmp(claims[i].name, OE_CLAIM_SIGNER_ID) == 0)
        {
            // Validate the signer id.
            if (memcmp(claims[i].value, m_enclave_mrsigner, 32) != 0)
            {
                TRACE_ENCLAVE("signer_id checking failed.");
                TRACE_ENCLAVE(
                    "signer_id %s", claims[i].value);

                for (int j = 0; j < 32; j++)
                {
                    TRACE_ENCLAVE(
                        "m_enclave_mrsigner[%d]=0x%0x\n",
                        j,
                        (uint8_t)m_enclave_mrsigner[j]);
                }

                TRACE_ENCLAVE("\n\n\n");

                for (int j = 0; j < 32; j++)
                {
                    TRACE_ENCLAVE(
                        "signer_id)[%d]=0x%0x\n",
                        j,
                        (uint8_t)claims[i].value[j]);
                }
                TRACE_ENCLAVE("m_enclave_mrsigner %s", m_enclave_mrsigner);
                goto exit;
            }
        }
        if (strcmp(claims[i].name, OE_CLAIM_PRODUCT_ID) == 0)
        {
            // Check the enclave's product id.
            if (claims[i].value[0] != 1)
            {
                TRACE_ENCLAVE("product_id checking failed.");
                goto exit;
            }
        }
        if (strcmp(claims[i].name, OE_CLAIM_SECURITY_VERSION) == 0)
        {
            // Check the enclave's security version.
            if (claims[1].value[0] < 1)
            {
                TRACE_ENCLAVE("security_version checking failed.");
                goto exit;
            }
        }
    }

    ret = true;
    TRACE_ENCLAVE("attestation succeeded.");
exit:
    // Shut down attester/verifier and free claims.
    oe_attester_shutdown();
    oe_verifier_shutdown();
    oe_free_claims(claims, claims_length);
    return ret;
}

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
 * Generate a report for the given data. The SHA256 digest of the data is
 * stored in the report_data field of the generated report.
 */
bool Attestation::generate_local_report(
    uint8_t* target_info_buffer,
    size_t target_info_size,
    const uint8_t* data,
    const size_t data_size,
    uint8_t** report_buf,
    size_t* local_report_buf_size)
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
    result = oe_get_evidence(&sgx_local_uuid, NULL, NULL, 0, target_info_buffer, target_info_size, report_buf, local_report_buf_size, NULL, 0);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_get_evidence failed.");
        goto exit;
    }

    ret = true;
    TRACE_ENCLAVE("generate_local_report succeeded.");
exit:
    return ret;
}

/**
 * Attest the given local report and accompanying data. It consists of the
 * following three steps:
 *
 * 1) The local report is first attested using the oe_verify_report API. This
 * ensures the authenticity of the enclave that generated the report.
 * 2) Next, to establish trust of the enclave that generated the report,
 * the mrsigner, product_id, isvsvn values are checked to  see if they are
 * predefined trusted values.
 * 3) Once the enclave's trust has been established, the validity of
 * accompanying data is ensured by comparing its SHA256 digest against the
 * report_data field.
 */
bool Attestation::attest_local_report(
    const uint8_t* local_report,
    size_t report_size,
    const uint8_t* data,
    size_t data_size)
{
    bool ret = false;
    uint8_t sha256[32];
    oe_report_t parsed_report = {0};
    oe_result_t result = OE_OK;
    oe_result_t verifier_result = OE_OK;
    oe_claim_t* claims = NULL;
    size_t claims_length = 0;

    // While attesting, the report being attested must not be tampered
    // with. Ensure that it has been copied over to the enclave.
    if (!oe_is_within_enclave(local_report, report_size))
    {
        TRACE_ENCLAVE("Cannot attest report in host memory. Unsafe.");
        goto exit;
    }

    TRACE_ENCLAVE("report_size = %ld", report_size);

    verifier_result = oe_verifier_initialize();
    if (verifier_result != OE_OK)
    {
        TRACE_ENCLAVE("oe_verifier_initialize failed.");
        goto exit;
    }

    // 1)  Validate the report's trustworthiness
    // Verify the report to ensure its authenticity.
    result = oe_verify_evidence(&sgx_local_uuid, local_report, report_size, NULL, 0, NULL, 0, &claims, &claims_length);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_verify_evidence failed (%s).\n", oe_result_str(result));
        goto exit;
    }

    TRACE_ENCLAVE("oe_verify_evidence succeeded\n");

    // Iterate through list of claims.
    for (size_t i = 0; i < OE_REQUIRED_CLAIMS_COUNT; i++) 
    {
        if (strcmp(claims[i].name, OE_CLAIM_SIGNER_ID) == 0)
        {
            // Validate the signer id.
            if (memcmp(claims[i].value, m_enclave_mrsigner, 32) != 0)
            {
                TRACE_ENCLAVE("signer_id checking failed.");
                TRACE_ENCLAVE(
                    "signer_id %s", parsed_report.identity.signer_id);

                for (int i = 0; i < 32; i++)
                {
                    TRACE_ENCLAVE(
                        "m_enclave_mrsigner[%d]=0x%0x\n",
                        i,
                        (uint8_t)m_enclave_mrsigner[i]);
                }

                TRACE_ENCLAVE("\n\n\n");

                for (int i = 0; i < 32; i++)
                {
                    TRACE_ENCLAVE(
                        "signer_id)[%d]=0x%0x\n",
                        i,
                        (uint8_t)parsed_report.identity.signer_id[i]);
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

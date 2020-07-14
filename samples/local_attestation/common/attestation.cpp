// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "attestation.h"
#include <string.h>
#include "log.h"
<<<<<<< HEAD
<<<<<<< HEAD
=======
#include <openenclave/internal/sgx/plugin.h>
>>>>>>> d4d1ca137... start
=======
>>>>>>> 9f69077da... delete include
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/verifier.h>

<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> 9e98f62a3... update references to old api
// SGX local attestation UUID.
static oe_uuid_t sgx_local_uuid = {OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};
oe_uuid_t selected_format;
<<<<<<< HEAD
=======
static oe_uuid_t sgx_local_uuid = {OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};
>>>>>>> d4d1ca137... start
=======
>>>>>>> 7d047d672... move format

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
<<<<<<< HEAD
<<<<<<< HEAD
    oe_result_t result = OE_OK;    
    oe_result_t attester_result = OE_OK;
    oe_result_t attester_format_result = OE_OK;
=======
    oe_result_t result = OE_OK;
    uint8_t* temp_buf = NULL;
<<<<<<< HEAD
    oe_uuid_t selected_format;
>>>>>>> d4d1ca137... start
=======
    
>>>>>>> 7d047d672... move format
=======
    oe_result_t result = OE_OK;    
<<<<<<< HEAD
>>>>>>> 776c751c6... test
=======
    oe_result_t attester_result = OE_OK;
    oe_result_t attester_format_result = OE_OK;
>>>>>>> ce88b01df... more bookkeeping

    if (m_crypto->Sha256(data, data_size, sha256) != 0)
    {
        goto exit;
    }

<<<<<<< HEAD
<<<<<<< HEAD
    // Initialize attester and use the SGX plugin.
    attester_result = oe_attester_initialize();
    if (attester_result != OE_OK)
    {
        TRACE_ENCLAVE("oe_attester_initialize failed.");
        goto exit;
    }
<<<<<<< HEAD

<<<<<<< HEAD
<<<<<<< HEAD
    
<<<<<<< HEAD
=======
    /*
>>>>>>> 0040203ee... remove select format
=======
    
>>>>>>> b47a6208b... revert
    // Select the attestation format.
    attester_format_result = oe_attester_select_format(&sgx_local_uuid, 1, &selected_format);
    if (attester_format_result != OE_OK)
    {
        TRACE_ENCLAVE("oe_attester_select_format failed.");
        goto exit;
    }
=======
    // // Select the attestation format.
    // attester_format_result = oe_attester_select_format(&sgx_local_uuid, 1, &selected_format);
    // if (attester_format_result != OE_OK)
    // {
    //     TRACE_ENCLAVE("oe_attester_select_format failed.");
    //     goto exit;
    // }
>>>>>>> 307b9451d... test without select format

    // Generate evidence based on the format selected by the attester.
<<<<<<< HEAD
<<<<<<< HEAD
    result = oe_get_evidence(&sgx_local_uuid, NULL, NULL, 0, target_info_buffer, target_info_size, report_buf, local_report_buf_size, NULL, 0);
<<<<<<< HEAD
=======
=======
    // Initialize attester and use the SGX plugin.
>>>>>>> 9e98f62a3... update references to old api
    oe_attester_initialize();
=======
>>>>>>> ce88b01df... more bookkeeping

    // Select the attestation format.
    attester_format_result = oe_attester_select_format(&sgx_local_uuid, 1, &selected_format);
    if (attester_format_result != OE_OK)
    {
        TRACE_ENCLAVE("oe_attester_select_format failed.");
        goto exit;
    }

<<<<<<< HEAD
    // To generate a local report that just needs to be attested by another
    // enclave running on the same platform, set flags to 0 in oe_get_report
    // call. This uses the EREPORT instruction to generate this enclave's local
    // report.
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    result = oe_get_evidence(&selected_format, NULL, NULL, 0, NULL, 0, report_buf, remote_report_buf_size, NULL, 0);
>>>>>>> d4d1ca137... start
=======
    result = oe_get_evidence(&selected_format, OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID, NULL, 0, NULL, 0, report_buf, remote_report_buf_size, NULL, 0);
>>>>>>> 3eeff28a2... isolate first batch of changes
=======
    result = oe_get_evidence(&selected_format, NULL, NULL, 0, NULL, 0, report_buf, remote_report_buf_size, NULL, 0);
>>>>>>> 03b34690a... revert flag
=======
    result = oe_get_evidence(&selected_format, OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID, NULL, 0, NULL, 0, report_buf, remote_report_buf_size, NULL, 0);
>>>>>>> 574431b0c... header
=======
    result = oe_get_evidence(&selected_format, NULL, NULL, 0, NULL, 0, report_buf, remote_report_buf_size, NULL, 0);
>>>>>>> 7d047d672... move format
=======
=======
    // Generate evidence based on the format selected by the attester.
<<<<<<< HEAD
>>>>>>> 62e639fb7... cleanup
    result = oe_get_evidence(&selected_format, NULL, NULL, 0, target_info_buffer, target_info_size, report_buf, local_report_buf_size, NULL, 0);
>>>>>>> e5c1b25bf... unblock
=======
>>>>>>> 0040203ee... remove select format
=======
    result = oe_get_evidence(&sgx_local_uuid, OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID , NULL, 0, target_info_buffer, target_info_size, report_buf, local_report_buf_size, NULL, 0);
>>>>>>> 0c95f321d... test without select format
=======
    result = oe_get_evidence(&sgx_local_uuid, NULL, NULL, 0, target_info_buffer, target_info_size, report_buf, local_report_buf_size, NULL, 0);
>>>>>>> 741075492... stable
=======
    result = oe_get_evidence(&sgx_local_uuid, NULL, NULL, 0, target_info_buffer, target_info_size, evidence_buf, local_evidence_buf_size, NULL, 0);
>>>>>>> 80b844401... reword
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_get_evidence failed.");
        goto exit;
    }
<<<<<<< HEAD
<<<<<<< HEAD

=======
    //*report_buf = temp_buf;
>>>>>>> ba3ab961e... remove
=======

>>>>>>> b749013df... remove
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
<<<<<<< HEAD
<<<<<<< HEAD
    oe_result_t verifier_result = OE_OK;
=======
>>>>>>> 3eeff28a2... isolate first batch of changes
=======
    oe_result_t verifier_result = OE_OK;
>>>>>>> ce88b01df... more bookkeeping
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

<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> ce88b01df... more bookkeeping
    verifier_result = oe_verifier_initialize();
    if (verifier_result != OE_OK)
    {
        TRACE_ENCLAVE("oe_verifier_initialize failed.");
        goto exit;
    }
<<<<<<< HEAD

    // 1)  Validate the report's trustworthiness
    // Verify the report to ensure its authenticity.
<<<<<<< HEAD
<<<<<<< HEAD
    result = oe_verify_evidence(&selected_format, local_report, report_size, NULL, 0, NULL, 0, &claims, &claims_length);
=======
    oe_verifier_initialize();
=======
>>>>>>> ce88b01df... more bookkeeping

<<<<<<< HEAD
    // 1)  Validate the report's trustworthiness
    // Verify the report to ensure its authenticity.
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    result = oe_verify_evidence(NULL, local_report, report_size, NULL, 0, NULL, 0, &claims, &claims_length);
>>>>>>> 3eeff28a2... isolate first batch of changes
=======
    result = oe_verify_evidence(&selected_format, local_report, report_size, NULL, 0, NULL, 0, &claims, &claims_length);
>>>>>>> c39008d41... verify
=======
    result = oe_verify_evidence(NULL, local_report, report_size, NULL, 0, NULL, 0, &claims, &claims_length);
>>>>>>> 9e5cea1f0... test null first param
=======
    result = oe_verify_evidence(&selected_format, local_report, report_size, NULL, 0, NULL, 0, &claims, &claims_length);
>>>>>>> b47a6208b... revert
=======
    result = oe_verify_evidence(&sgx_local_uuid, local_report, report_size, NULL, 0, NULL, 0, &claims, &claims_length);
>>>>>>> 307b9451d... test without select format
=======
    result = oe_verify_evidence(NULL, local_report, report_size, NULL, 0, NULL, 0, &claims, &claims_length);
>>>>>>> 0c95f321d... test without select format
=======
    result = oe_verify_evidence(&sgx_local_uuid, local_report, report_size, NULL, 0, NULL, 0, &claims, &claims_length);
>>>>>>> 741075492... stable
=======
    // 1)  Validate the evidence's trustworthiness
    // Verify the evidence to ensure its authenticity.
    result = oe_verify_evidence(&sgx_local_uuid, local_evidence, evidence_size, NULL, 0, NULL, 0, &claims, &claims_length);
>>>>>>> 80b844401... reword
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_verify_evidence failed (%s).\n", oe_result_str(result));
        goto exit;
    }

    TRACE_ENCLAVE("oe_verify_evidence succeeded\n");

<<<<<<< HEAD
<<<<<<< HEAD
    // Iterate through list of claims.
    for (size_t i = 0; i < OE_REQUIRED_CLAIMS_COUNT; i++) 
=======
    // 2) validate the enclave identity's signed_id is the hash of the public
    // signing key that was used to sign an enclave. Check that the enclave was
    // signed by an trusted entity.
    if (memcmp(claims[4].value, m_enclave_mrsigner, 32) != 0)
>>>>>>> e5c1b25bf... unblock
    {
<<<<<<< HEAD
        if (strcmp(claims[i].name, OE_CLAIM_SIGNER_ID) == 0)
=======
        TRACE_ENCLAVE("signer_id checking failed.");
        TRACE_ENCLAVE(
            "signer_id %s", parsed_report.identity.signer_id);

        for (int i = 0; i < 32; i++)
>>>>>>> 9e98f62a3... update references to old api
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
<<<<<<< HEAD
            // Check the enclave's product id.
            if (claims[i].value[0] != 1)
            {
                TRACE_ENCLAVE("product_id checking failed.");
                goto exit;
            }
=======
            TRACE_ENCLAVE(
                "signer_id)[%d]=0x%0x\n",
                i,
                (uint8_t)parsed_report.identity.signer_id[i]);
>>>>>>> 9e98f62a3... update references to old api
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
<<<<<<< HEAD
=======
        TRACE_ENCLAVE("m_enclave_mrsigner %s", m_enclave_mrsigner);
        goto exit;
    }

    // Check the enclave's product id and security version
    // See enc.conf for values specified when signing the enclave.
    if (claims[5].value[0] != 1)
    {
        TRACE_ENCLAVE("product_id checking failed.");
        goto exit;
    }

    if (claims[1].value[0] < 1)
    {
        TRACE_ENCLAVE("security_version checking failed.");
        goto exit;
>>>>>>> 3eeff28a2... isolate first batch of changes
=======
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
>>>>>>> 556b58238... check against names
    }

    ret = true;
    TRACE_ENCLAVE("attestation succeeded.");
exit:
<<<<<<< HEAD
<<<<<<< HEAD
    // Shut down attester/verifier and free claims.
    oe_attester_shutdown();
    oe_verifier_shutdown();
=======
    // Shut down verifier and free evidence and claims.
    oe_verifier_shutdown();
    oe_free_evidence(local_report);
>>>>>>> 9e98f62a3... update references to old api
=======
    // Shut down attester/verifier and free claims.
    oe_attester_shutdown();
    oe_verifier_shutdown();
>>>>>>> 776c751c6... test
    oe_free_claims(claims, claims_length);
    return ret;
}

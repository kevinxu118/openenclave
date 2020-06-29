// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "attestation.h"
#include <string.h>
#include "log.h"
#include <../host/my_plugin_guid.h>
#include <../host/my_plugin_attester.h>

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
    size_t* remote_report_buf_size)
{
    bool ret = false;
    uint8_t sha256[32];
    oe_result_t result = OE_OK;

    if (m_crypto->Sha256(data, data_size, sha256) != 0)
    {
        goto exit;
    }

    struct my_plugin_attester_opt_params_t* opt_params = (my_plugin_attester_opt_params_t*) oe_malloc(sizeof(struct my_plugin_attester_opt_params_t));

    opt_params->sha256 = sha256;
    opt_params->target_info_buffer = target_info_buffer;
    opt_params->target_info_size = target_info_size;

    // To generate a local report that just needs to be attested by another
    // enclave running on the same platform, set flags to 0 in oe_get_report
    // call. This uses the EREPORT instruction to generate this enclave's local
    // report.

    result = oe_get_evidence(
        MY_PLUGIN_UUID,
        0,
        NULL,
        0,
        opt_params,
        sizeof(opt_params),
        report_buf,
        remote_report_buf_size,
        NULL,
        0);

    return result;

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
    oe_claim_t** required_claims = (oe_claim_t **)oe_malloc(sizeof(oe_claim_t *));
    size_t* claims_size = (size_t *)oe_malloc(sizeof(size_t));

    // While attesting, the report being attested must not be tampered
    // with. Ensure that it has been copied over to the enclave.
    if (!oe_is_within_enclave(local_report, report_size))
    {
        TRACE_ENCLAVE("Cannot attest report in host memory. Unsafe.");
        goto exit;
    }

    TRACE_ENCLAVE("report_size = %ld", report_size);

    // 1) verify evidence
    result = oe_verify_evidence(
        MY_PLUGIN_UUID,
        local_report,
        report_size,
        NULL,
        0,
        NULL,
        0,
        required_claims,
        claims_size);

    oe_claim_t* my_claims = *required_claims;

    if (result != OE_OK)
    {
        TRACE_ENCLAVE(
            "oe_verify_evidence failed (%s).\n", oe_result_str(result));
        goto exit;
    }

    TRACE_ENCLAVE("oe_verify_evidence succeeded\n");


    // Iterate through returned claims.

    for(size_t j = 0; j < *claims_size; j++) {

      // 2) validate the enclave identity's signed_id is the hash of the public
      // signing key that was used to sign an enclave. Check that the enclave was
      // signed by an trusted entity.
      if (strcmp(my_claims[j].name, OE_CLAIM_SIGNER_ID) == 0) {

        if (memcmp(my_claims[j].value, m_enclave_mrsigner, 32) != 0) {
          TRACE_ENCLAVE("identity.signer_id checking failed.");
          TRACE_ENCLAVE(
            "identity.signer_id %s", my_claims[j].value);

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
                "parsedReport.identity.signer_id)[%d]=0x%0x\n",
                i,
                (uint8_t)my_claims[j].value[i]);
          }
          TRACE_ENCLAVE("m_enclave_mrsigner %s", m_enclave_mrsigner);
          goto exit;
        }
      }

      // Check the enclave's product id and security version
      // See enc.conf for values specified when signing the enclave.
      if (strcmp(my_claims[j].name, OE_CLAIM_PRODUCT_ID) == 0) {
        if (my_claims[j].value[0] != 1)
        {
          TRACE_ENCLAVE("identity.product_id checking failed.");
          goto exit;
        }
      }

      if (strcmp(my_claims[j].name, OE_CLAIM_SECURITY_VERSION) == 0) {
        if (*(my_claims[j].value) < 1)
        {
          TRACE_ENCLAVE("identity.security_version checking failed.");
          goto exit;
        }
      }

      // 3) Validate the report data
      //    The report_data has the hash value of the report data
      if (strcmp(my_claims[j].name, "report_data") == 0) {
        if (m_crypto->Sha256(data, data_size, sha256) != 0)
        {
          goto exit;
        }

        if (memcmp(my_claims[j].value, sha256, sizeof(sha256)) != 0)
        {
          TRACE_ENCLAVE("SHA256 mismatch.");
          goto exit;
        }
      }
    }

    ret = true;
    TRACE_ENCLAVE("attestation succeeded.");
  exit:
    return ret;
}

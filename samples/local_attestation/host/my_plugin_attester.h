#include "my_plugin_guid.h"

/* Helper function to create the plugin. */
oe_attester_t* my_plugin_attester();

/* Example struct used for config data for my_plugin->on_register. */
/*
struct my_plugin_attester_config_data_t
{
  uint8_t* example_data_onregister;
};
*/

/* Example struct used as input parameters for my_plugin->get_evidence. */
struct my_plugin_attester_opt_params_t
{
    uint8_t sha256[32];
    uint8_t* target_info_buffer;
    size_t target_info_size;
};

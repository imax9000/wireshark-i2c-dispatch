#include <stdint.h>
#include <stdio.h>

#include "config.h"
#include <epan/decode_as.h>
#include <epan/packet.h>
#include <epan/proto_data.h>

static int proto_i2c = -1;
static int proto_i2c_dispatch = -1;

static dissector_table_t addr_dissector_table;

static int hf_i2c_addr = -1;

static void i2c_addr_prompt(packet_info *pinfo _U_, char *result) {
  snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Interpret I2C messages as");
}

static void *i2c_addr_value(packet_info *pinfo) {
  return (void *)p_get_proto_data(pinfo->pool, pinfo, hf_i2c_addr,
                                  pinfo->curr_layer_num);
}

void proto_register_i2c_dispatch(void) {
  proto_i2c = proto_get_id_by_filter_name("i2c");

  if (proto_i2c < 0) {
    return;
  }

  header_field_info *addr_finfo = proto_registrar_get_byname("i2c.addr");
  if (!addr_finfo) {
    return;
  }
  hf_i2c_addr = addr_finfo->id;

  proto_i2c_dispatch = proto_register_protocol_in_name_only(
      "I2C dispatch by address", "I2C address", "i2c_addr", proto_i2c,
      FT_PROTOCOL);

  addr_dissector_table = register_dissector_table(
      "i2c.addr", "I2C address", proto_i2c, FT_UINT8, BASE_HEX);

  static build_valid_func addr_da_build_value[1] = {i2c_addr_value};
  static decode_as_value_t addr_da_values = {i2c_addr_prompt, 1,
                                             addr_da_build_value};
  static decode_as_t addr_da = {"i2c",
                                "i2c.addr",
                                1,
                                0,
                                &addr_da_values,
                                NULL,
                                NULL,
                                decode_as_default_populate_list,
                                decode_as_default_reset,
                                decode_as_default_change,
                                NULL};
  register_decode_as(&addr_da);
}

static int dissect_i2c_dispatch(tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *tree _U_, void *data _U_) {
  header_field_info *addr_finfo = proto_registrar_get_byname("i2c.addr");
  if (!addr_finfo) {
    return 0;
  }

  GPtrArray *found = proto_get_finfo_ptr_array(tree, addr_finfo->id);
  bool have_addr = false;
  uint32_t addr;
  if (found) {
    for (unsigned i = 0; i < found->len; i++) {
      field_info *finfo = (field_info *)g_ptr_array_index(found, i);
      addr = fvalue_get_uinteger(&finfo->value);
      have_addr = true;
      break;
    }
  }
  if (!have_addr || addr > 0xff) {
    return 0;
  }

  int n = dissector_try_uint(addr_dissector_table, addr, tvb, pinfo, tree);
  if (n == 0)
    return 0;
  return n + 1;
}

void proto_reg_handoff_i2c_dispatch(void) {
  static dissector_handle_t i2c_dispatch_handle;

  if (proto_i2c < 0) {
    return;
  }

  i2c_dispatch_handle =
      create_dissector_handle(dissect_i2c_dispatch, proto_i2c_dispatch);
  dissector_add_for_decode_as("i2c.message", i2c_dispatch_handle);

  // Has no effect, probably it gets reset later by something like loading
  // "Decode As..." from preferences.
  dissector_change_payload("i2c.message", i2c_dispatch_handle);
}

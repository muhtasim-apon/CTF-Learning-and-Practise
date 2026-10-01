Solved.

  Flag:

  bupctf{QU4Y_D07do7_s7Rip_PreF1x_HM4C_CleRk}

  Core exploit path was:

  /preview?slip=....//warehouse_meta/signing.key

  That leaks the signing key because the app strips ../ once,
  turning ....// into ../, and then a bad prefix check allows
  access to the sibling warehouse_meta tree. Using the leaked
  key, I forged the quay_session role from reader to clerk and
  opened /cabinet.

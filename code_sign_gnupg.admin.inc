<?php

function code_sign_gnupg_admin_form($form, &$form_state) {
  require_once __DIR__ . '/gnupg.codesign.inc';
  $key_opts = code_sign_gnupg_get_private_keys();

  $form['#config'] = 'code_sign_gnupg.settings';
  $form['default_signing_key'] = array(
    '#type' => 'select',
    '#title' => t('Default Signing Key'),
    '#options' => array_column($key_opts, 'name', 'profile_id'),
    '#default_value' => config('code_sign_gnupg.settings')->get('default_signing_key'),
  );

  return system_settings_form($form);
}

/**
 * Import a new public or private key.
 */
function code_sign_gnupg_admin_import_key_form($form, &$form_state) {
  $form['import_key'] = array(
    '#type' => 'file',
    '#title' => t('Import Key'),
    '#description' => t('Use this to import public or secret keys.  Filename extension must be one of gnupg, gpg, or pgp.'),
  );

  $form['submit'] = array(
    '#type' => 'submit',
    '#value' => 'Submit',
  );
  $form['#submit'][] = 'code_sign_gnupg_admin_import_key_form_submit';

  return $form;
}

function code_sign_gnupg_admin_import_key_form_submit(&$form, &$form_state) {
  // Get the file.
  $validators = array('file_validate_extensions' => array('gnupg gpg pgp'));
  $file = file_save_upload('import_key', $validators, 'temporary://');

  if ($file) {
    // Import the key into the GnuPG keychain.
    $gnupg = gnupg_init();
    $key = file_get_contents($file->uri);
    $result = gnupg_import($gnupg, $key);

    // TODO: Improve reporting
    // dpm($result);

    // No need to keep it around, we're done with it.
    file_delete($file->fid);
  }
}


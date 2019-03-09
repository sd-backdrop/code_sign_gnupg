<?php

// Huge thanks to Jens Erat for his answer on StackOverflow:
// https://stackoverflow.com/questions/32787007/what-do-returned-values-of-php-gnupg-signature-verification-mean

// Validity field.
define('GPGME_VALIDITY_UNKNOWN', 0);
define('GPGME_VALIDITY_UNDEFINED', 1);
define('GPGME_VALIDITY_NEVER', 2);
define('GPGME_VALIDITY_MARGINAL', 3);
define('GPGME_VALIDITY_FULL', 4);
define('GPGME_VALIDITY_ULTIMATE', 5);

// Summary field.
define('GPGME_SIGSUM_VALID', 0x0001);  /* The signature is fully valid.  */
define('GPGME_SIGSUM_GREEN', 0x0002);  /* The signature is good.  */
define('GPGME_SIGSUM_RED', 0x0004);  /* The signature is bad.  */
define('GPGME_SIGSUM_KEY_REVOKED', 0x0010);  /* One key has been revoked.  */
define('GPGME_SIGSUM_KEY_EXPIRED', 0x0020);  /* One key has expired.  */
define('GPGME_SIGSUM_SIG_EXPIRED', 0x0040);  /* The signature has expired.  */
define('GPGME_SIGSUM_KEY_MISSING', 0x0080);  /* Can't verify: key missing.  */
define('GPGME_SIGSUM_CRL_MISSING', 0x0100);  /* CRL not available.  */
define('GPGME_SIGSUM_CRL_TOO_OLD', 0x0200);  /* Available CRL is too old.  */
define('GPGME_SIGSUM_BAD_POLICY', 0x0400);  /* A policy was not met.  */
define('GPGME_SIGSUM_SYS_ERROR', 0x0800);  /* A system error occured.  */

function code_sign_gnupg_sign($profile, $data, $options = array()) {
  $signature = array();

  $gpg = gnupg_init();
  gnupg_seterrormode($gpg, gnupg::ERROR_EXCEPTION);
  gnupg_addsignkey($gpg, $profile);
  gnupg_setsignmode($gpg, GNUPG_SIG_MODE_DETACH);
  $signature = gnupg_sign($gpg, $data);

  if (!$signature) {
    watchdog('code_sign_gnupg', 'Could not generate signature, gnupg returned: @error', array('@error' => gnupg_geterror($gpg)), WATCHDOG_WARNING);
    return NULL;
  }

  return $signature;
}

/**
 * Verify the GnuPG signature of some data.
 * @param $data
 *   The data to check.
 * @param $signature
 *   The signature to verify, or NULL if the signature is embedded in $data.
 * @param $options
 *   Unused.
 * @return
 *   Needs work.
 */
function code_sign_gnupg_verify($data, $signature = NULL, $options = array()) {
  $gpg = gnupg_init();
  code_sign_gnupg_import_keys($gpg);
  if (!$gpg) {
    watchdog('codesign', 'GnuPG unavailable.', array(), WATCHDOG_ERROR);
    return FALSE;
  }

  // Check the signature.
  $results = gnupg_verify($gpg, $data, $signature);

  // TODO: Handle multiple messages better.
  $success = FALSE;
  $messages = array();
  if ($results) {
    foreach($results as $result) {
      if ($result['status'] < 0x04) {
        $key = gnupg_keyinfo($gpg, $result['fingerprint']);
        $success = TRUE;
        $messages[] = t('Valid signature from @signer, signed at @time', array(
          '@signer' => $key[0]['uids'][0]['uid'],
          '@time' => format_date($result['timestamp']),
        ));
      }
      else {
        $messages[] = t('Signature is invalid: @error', array(
          '@error' => code_sign_gnupg_summary_translation($result['summary']),
        ));
      }
    }
    $message = implode('<br/>', $messages);
  }
  else {
    $message = t('Error while checking signature: @error', array('@error' => gnupg_geterror($gpg)));
  }

  return array(
    'success' => $success,
    'message' => $message,
    'gnupg_results' => $results,
  );
}

function code_sign_gnupg_status() {
  $rows = array();
  foreach (code_sign_gnupg_get_public_keys() as $k) {
    $rows[] = array(
      check_plain($k['name']),
      check_plain($k['key_info']['keyid']),
      format_date($k['key_info']['expires']),
    );
  }

  return array(
    '#theme' => 'table',
    '#header' => array('Key name', 'Key ID', 'Expires'),
    '#rows' => $rows,
  );
}

function code_sign_gnupg_get_public_keys() {
  $valid_keys = &backdrop_static(__FUNCTION__, array());

  if (!$valid_keys) {
    $gpg = gnupg_init();

    $keys = gnupg_keyinfo($gpg, '');
    foreach ($keys as $k) {
      foreach ($k['subkeys'] as $id => $sk) {
        $valid_keys[$sk['fingerprint']] = array(
          'name' => $k['uids'][0]['uid'],
          'profile_id' => $sk['fingerprint'],
          'key_info' => $sk,
        );
      }
    }
  }

  return $valid_keys;
}

/**
 * php-gnupg doesn't set the 'is_secret' flag, ever.  The only way to see if
 * a key is valid for signing is to try it.
 *
 * @return
 *   An array of valid keys indexed by their fingerprint.
 */
function code_sign_gnupg_get_private_keys() {
  $gpg = gnupg_init();
  gnupg_seterrormode($gpg, gnupg::ERROR_EXCEPTION);

  $keys = gnupg_keyinfo($gpg, '');
  $valid_keys = array();
  foreach ($keys as $k) {
    foreach ($k['subkeys'] as $id => $sk) {
      gnupg_clearsignkeys($gpg);
      if ($sk['can_sign']) {
        try {
          gnupg_addsignkey($gpg, $sk['fingerprint']);
        }
        catch (Exception $e) {
          continue;
        }
        $valid_keys[$sk['fingerprint']] = array(
          'name' => $k['uids'][0]['uid'],
          'profile_id' => $sk['fingerprint'],
          'key_info' => $k,
        );
      }
    }
  }

  return $valid_keys;
}

/**
 * Attempt to import all the keys in the GnuPG keys directory.
 *
 * @param $gnupg
 *   A valid GnuPG resource as returned by gnupg_init().
 * @return
 *   FALSE on failure, the fingerprint of the last imported key on success, or
 *   NULL if the gnupg extension isn't loaded.
 */
function code_sign_gnupg_import_keys($gnupg) {
  $result = NULL;
  return $result;
  if (extension_loaded('gnupg')) {
    foreach (glob(BACKDROP_ROOT . '/core/misc/codesign/gnupg/*.gpg') as $file) {
      if ($key = file_get_contents($file)) {
        $result = gnupg_import($gnupg, $key);
      }
    }
  }
  return ($result) ? $result['fingerprint'] : $result;
}

function code_sign_gnupg_summary_translation($summary) {
  $reasons = array();

  if ($summary & GPGME_SIGSUM_VALID) {
    $reasons[] = t('the signature is valid.');
  }
  if ($summary & GPGME_SIGSUM_GREEN) {
    $reasons[] = t('the signature is good.');
  }
  if ($summary & GPGME_SIGSUM_RED) {
    $reasons[] = t('the signature is bad');
  }
  if ($summary & GPGME_SIGSUM_KEY_REVOKED) {
    $reasons[] = t('a key has been revoked');
  }
  if ($summary & GPGME_SIGSUM_KEY_EXPIRED) {
    $reasons[] = t('a key has expired');
  }
  if ($summary & GPGME_SIGSUM_SIG_EXPIRED) {
    $reasons[] = t('the signature has expired');
  }
  if ($summary & GPGME_SIGSUM_KEY_MISSING) {
    $reasons[] = t('a key is missing');
  }
  if ($summary & GPGME_SIGSUM_CRL_MISSING) {
    $reasons[] = t('the CRL not available');
  }
  if ($summary & GPGME_SIGSUM_CRL_TOO_OLD) {
    $reasons[] = t('the available CRL is too old');
  }
  if ($summary & GPGME_SIGSUM_BAD_POLICY) {
    $reasons[] = t('a policy was not met');
  }
  if ($summary & GPGME_SIGSUM_SYS_ERROR) {
    $reasons[] = t('a system error occured');
  }

  return implode(', ', $reasons);
}


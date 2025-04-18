<?php
/**
 * This code is licensed under AGPLv3 license or Afterlogic Software License
 * if commercial version of the product was purchased.
 * For full statements of the licenses see LICENSE-AFTERLOGIC and LICENSE-AGPL3 files.
 */

namespace Aurora\Modules\MailChangePasswordIspconfigPlugin;

use Aurora\Modules\Mail\Models\MailAccount;
use Aurora\System\Notifications;

/**
 * Allows users to change passwords on their email accounts in ISPConfig.
 *
 * @license https://www.gnu.org/licenses/agpl-3.0.html AGPL-3.0
 * @license https://afterlogic.com/products/common-licensing Afterlogic Software License
 * @copyright Copyright (c) 2023, Afterlogic Corp.
 *
 * @property Settings $oModuleSettings
 *
 * @package Modules
 */
class Module extends \Aurora\System\Module\AbstractModule
{
    public function init()
    {
        $this->subscribeEvent('Mail::Account::ToResponseArray', array($this, 'onMailAccountToResponseArray'));
        $this->subscribeEvent('ChangeAccountPassword', array($this, 'onChangeAccountPassword'));
    }

    /**
     * @return Module
     */
    public static function getInstance()
    {
        return parent::getInstance();
    }

    /**
     * @return Module
     */
    public static function Decorator()
    {
        return parent::Decorator();
    }

    /**
     * @return Settings
     */
    public function getModuleSettings()
    {
        return $this->oModuleSettings;
    }

    /**
     * Adds to account response array information about if allowed to change the password for this account.
     * @param array $aArguments
     * @param mixed $mResult
     */
    public function onMailAccountToResponseArray($aArguments, &$mResult)
    {
        $oAccount = $aArguments['Account'];

        if ($oAccount && $this->checkCanChangePassword($oAccount)) {
            if (!isset($mResult['Extend']) || !is_array($mResult['Extend'])) {
                $mResult['Extend'] = [];
            }
            $mResult['Extend']['AllowChangePasswordOnMailServer'] = true;
        }
    }

    /**
     * Tries to change password for account if allowed.
     * @param array $aArguments
     * @param mixed $mResult
     */
    public function onChangeAccountPassword($aArguments, &$mResult)
    {
        $bPasswordChanged = false;
        $bBreakSubscriptions = false;

        $oAccount = $aArguments['Account'] instanceof MailAccount ? $aArguments['Account'] : false;
        if ($oAccount && $this->checkCanChangePassword($oAccount) && $oAccount->getPassword() === $aArguments['CurrentPassword']) {
            $bPasswordChanged = $this->changePassword($oAccount, $aArguments['NewPassword']);
            $bBreakSubscriptions = true; // break if mail server plugin tries to change password in this account.
        }

        if (is_array($mResult)) {
            $mResult['AccountPasswordChanged'] = $mResult['AccountPasswordChanged'] || $bPasswordChanged;
        }

        return $bBreakSubscriptions;
    }

    /**
     * Checks if allowed to change password for account.
     * @param \Aurora\Modules\Mail\Models\MailAccount $oAccount
     * @return bool
     */
    protected function checkCanChangePassword($oAccount)
    {
        $bFound = in_array('*', $this->oModuleSettings->SupportedServers);

        if (!$bFound) {
            $oServer = $oAccount->getServer();

            if ($oServer && in_array($oServer->IncomingServer, $this->oModuleSettings->SupportedServers)) {
                $bFound = true;
            }
        }

        return $bFound;
    }

    protected function crypt_password($cleartext_password)
    {
        if (defined('CRYPT_SHA512') && CRYPT_SHA512 == 1) {
            $salt = '$6$rounds=5000$';
            $salt_length = 16;
        } elseif (defined('CRYPT_SHA256') && CRYPT_SHA256 == 1) {
            $salt = '$5$rounds=5000$';
            $salt_length = 16;
        } else {
            $salt = '$1$';
            $salt_length = 12;
        }

        if (function_exists('openssl_random_pseudo_bytes')) {
            $salt .= substr(bin2hex(openssl_random_pseudo_bytes($salt_length)), 0, $salt_length);
        } else {
            $base64_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./';
            for ($n = 0; $n < $salt_length; $n++) {
                $salt .= $base64_alphabet[mt_rand(0, 63)];
            }
        }
        $salt .= "$";
        return crypt($cleartext_password, $salt);
    }

    /**
     * Tries to change password for account.
     * @param \Aurora\Modules\Mail\Models\MailAccount $oAccount
     * @param string $sPassword
     * @return boolean
     * @throws \Aurora\System\Exceptions\ApiException
     */
    protected function changePassword($oAccount, $sPassword)
    {
        $bResult = false;
        $sPassCurr = $oAccount->getPassword();
        if (0 < strlen($sPassCurr) && $sPassCurr !== $sPassword) {
            $config_dbuser = $this->oModuleSettings->DbUser;
            $config_dbpass = $this->oModuleSettings->DbPass;
            $config_dbname = $this->oModuleSettings->DbName;
            $config_dbhost = $this->oModuleSettings->DbHost;

            if ($config_dbpass && !\Aurora\System\Utils::IsEncryptedValue($config_dbpass)) {
                $this->setConfig('DbPass', \Aurora\System\Utils::EncryptValue($config_dbpass));
                $this->saveModuleConfig();
            } else {
                $config_dbpass = \Aurora\System\Utils::DecryptValue($config_dbpass);
            }

            $mysqlcon = mysqli_connect($config_dbhost, $config_dbuser, $config_dbpass, $config_dbname);
            if ($mysqlcon) {
                $sql = "SELECT * FROM mail_user WHERE login='" . $oAccount->IncomingLogin . "'";
                $result = mysqli_query($mysqlcon, $sql);
                $aUser = mysqli_fetch_array($result);
                $sPassStored = stripslashes($aUser['password']);
                $sSalt = substr($sPassStored, 0, 1 + strrpos($sPassStored, '$'));
                if (crypt(stripslashes($sPassCurr), $sSalt) != $sPassStored) {
                    throw new \Aurora\System\Exceptions\ApiException(Notifications::AccountOldPasswordNotCorrect);
                } else {
                    $sPasshash = $this->crypt_password($sPassword);
                    $sql = "UPDATE mail_user SET password='" . $sPasshash . "' WHERE email='" . $oAccount->IncomingLogin . "'";
                    $bResult = mysqli_query($mysqlcon, $sql);
                    if (!$bResult) {
                        throw new \Aurora\System\Exceptions\ApiException(Notifications::CanNotChangePassword);
                    }
                }
                mysqli_close($mysqlcon);
            } else {
                throw new \Aurora\System\Exceptions\ApiException(Notifications::CanNotChangePassword);
            }
        }
        return $bResult;
    }
}

<?php
/**
 * This code is licensed under AGPLv3 license or Afterlogic Software License
 * if commercial version of the product was purchased.
 * For full statements of the licenses see LICENSE-AFTERLOGIC and LICENSE-AGPL3 files.
 */

namespace Aurora\Modules\MailChangePasswordIspconfigPlugin;

use Aurora\System\SettingsProperty;

/**
 * @property bool $Disabled
 * @property array $SupportedServers
 * @property string $DbUser
 * @property string $DbPass
 * @property string $DbName
 * @property string $DbHost
 */

class Settings extends \Aurora\System\Module\Settings
{
    protected function initDefaults()
    {
        $this->aContainer = [
            "Disabled" => new SettingsProperty(
                false,
                "bool",
                null,
                "Setting to true disables the module",
            ),
            "SupportedServers" => new SettingsProperty(
                [
                    "*"
                ],
                "array",
                null,
                "If IMAP Server value of the mailserver is in this list, password change is enabled for it. * enables it for all the servers.",
            ),
            "DbUser" => new SettingsProperty(
                "",
                "string",
                null,
                "Defines username for accessing ISPConfig database",
            ),
            "DbPass" => new SettingsProperty(
                "",
                "string",
                null,
                "Defines password for accessing ISPConfig database",
            ),
            "DbName" => new SettingsProperty(
                "",
                "string",
                null,
                "Defines name of ISPConfig database",
            ),
            "DbHost" => new SettingsProperty(
                "localhost",
                "string",
                null,
                "Defines hostname of ISPConfig database",
            ),
        ];
    }
}

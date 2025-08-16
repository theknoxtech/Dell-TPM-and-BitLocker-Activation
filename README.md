# Activate-BitLocker.ps1 PowerShell Script

**Author:** Jon Witherspoon **Version:** 1.0.0 **Date:** 2025-08-11

## 📜 Overview

This script automates the process of enabling BitLocker Drive Encryption on the primary system drive (`C:`). It is specifically designed to work with Dell computers by leveraging the `DellBiosProvider` module to manage BIOS settings, such as activating the TPM chip, which is a prerequisite for BitLocker. The script ensures that both a TPM and a Recovery Password protector are added for security and recoverability.

## ⚙️ Prerequisites

Before running this script, ensure your system meets the following requirements:

- **Hardware:** A Dell computer with a TPM (Trusted Platform Module) chip.
    
- **PowerShell Version:** 5.1 or higher.
    
- **Execution Policy:** The script will attempt to set the execution policy to `Bypass` for its own process. However, your system's group policy must not override this setting.
    
- **Required Modules:**
    
    - `DellBiosProvider`: The script will attempt to automatically install this module from the PowerShell Gallery if it is not found. An active internet connection is required for this.
        
- **Permissions:** The script **must be run with administrative privileges** to manage BitLocker and BIOS settings.
    

## 🚀 Installation & Setup

1. **Download:** Place the `Activate-BitLocker.ps1` script in a directory on the target machine.
    
2. **Unblock File (Optional):** If you downloaded the script from the internet, you may need to unblock it first. Open a PowerShell terminal and run:
    
    ```powershell
    Unblock-File -Path ".\Activate-BitLocker.ps1"
    ```
    
3. **No Configuration Needed:** The script is designed to run without manual configuration of variables. It automatically handles paths and settings.
    

## 💡 Usage

To execute the script, open an elevated PowerShell terminal (Run as Administrator), navigate to the script's directory, and run the following command. The script does not accept any parameters.

### Basic Execution

```powershell
	.\Activate-BitLocker.ps1
```

The script is idempotent, meaning it can be run multiple times. It checks the current state of BitLocker and the TPM and only performs the actions necessary to reach the desired state.

**Note:** A system reboot may be required after the script enables TPM in the BIOS. The script will notify you if a reboot is needed. You must re-run the script after the reboot to complete the BitLocker encryption process.

## ✨ Examples

### Example 1: First-Time Execution on a Dell Machine

This is the standard use case. The script will perform a series of checks and actions.

```powershell
# Run with Administrator privileges
.\Activate-BitLocker.ps1
```

**Expected Workflow:**

1. Checks if the `DellBiosProvider` module is installed. If not, it installs it.
    
2. Checks if the TPM is ready. If not, it will:
    
    - Set a temporary BIOS administrator password.
        
    - Enable TPM Security in the BIOS.
        
    - Remove the temporary BIOS password.
        
    - Prompt for a reboot.
        
3. After reboot and re-running the script, it will:
    
    - Verify the TPM is ready.
        
    - Enable BitLocker on the C: drive with a TPM protector.
        
    - Add a recovery password key protector.
        
4. A log file will be created at `C:\Windows\LTSvc\packages\Activate-Blocker\activate_bitlocker.txt`.
    

## 🔧 Code Breakdown

This script is composed of several key functions to manage the complex workflow of enabling BitLocker on Dell hardware.

### State Detection Functions

- `Get-TPMState`: Queries the system's TPM chip and returns an object detailing if it is present, enabled, and ready.
    
- `Get-BitlockerState`: Checks the status of BitLocker on the C: drive, including its encryption status, protection status, and existing key protectors.
    

### Core Logic

The main part of the script is a large `Switch` statement that evaluates the current state of the system (`$bitlocker_settings`) and determines the next logical step.

- If the TPM is not ready, it proceeds to the Dell BIOS modification section.
    
- If the drive is already encrypted but missing protectors, it adds them.
    
- If the TPM is ready and the drive is unencrypted, it calls `Set-BitlockerState` to enable encryption.
    

### Dell BIOS Management

- This section, triggered when the TPM is not ready, uses the `DellBiosProvider` module to interact with BIOS settings.
    
- It temporarily sets a BIOS password to allow changes, enables the TPM, and then removes the password to leave the system in a clean state.
    
- It uses a file-based checkpoint (`CheckPoint_1`) to manage its state across reboots, ensuring it doesn't repeat steps unnecessarily.
    

### Logging

- `New-BitlockerLog`: A robust logging function that outputs messages to both the console and a persistent log file. This is crucial for troubleshooting issues on remote machines.
    

## ⚠️ Troubleshooting

|Issue|Cause|Resolution|
|---|---|---|
|`Set-ExecutionPolicy : ... overridden by a policy...`|A Group Policy Object (GPO) is enforcing a more restrictive execution policy.|The script cannot override GPO. The policy must be adjusted, or the script must be run on a machine without this restriction.|
|`Install-Module : The term 'Install-Module' is not recognized...`|The PowerShellGet module is not available or the PowerShell version is very old.|Ensure you are running PowerShell 5.1 or newer. Run `Get-Module PowerShellGet -ListAvailable` to check for the module.|
|Script fails to set BIOS password.|An unknown, pre-existing BIOS administrator password is set.|The script cannot proceed. The existing BIOS password must be cleared manually before re-running the script.|
|Script fails with `DriveNotFoundException` for `DellSmbios:`|The `DellBiosProvider` module did not load correctly.|Ensure the module is installed correctly and try importing it manually with `Import-Module -Name DellBIOSProvider -Force`.|
|A reboot is required.|The script enabled the TPM in the BIOS, which requires a full system restart to take effect.|Reboot the computer and then run the script again. The script will pick up where it left off and proceed with encryption.|

## 🪛 RMM Support

- Script can be used with an RMM.
- Script can fully automate the process of ensuring the TPM and BitLocker are enabled on Dell computers.
- To fully automate this process you will need to have your tooling setup with a secondary script to pull the BitLocker key for storage in Entra, Active Directory, or other place of your choosing.


## 🤝 Contributing

  Contributions, issues, and feature requests are welcome! Feel free to check the [issues page]([https://github.com/theknoxtech/Dell-TPM-and-BitLocker-Activation/issues]) for this project to see how you can help.
  

## 📄 License

This project is unlicensed and free to use.
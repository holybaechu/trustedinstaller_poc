use core::fmt;
use std::ffi::c_void;
use windows::{
    core::{w, HSTRING, PCWSTR, PWSTR},
    Win32::{
        Foundation::{CloseHandle, HANDLE, HWND, LUID},
        Security::{
            AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, TokenElevation, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY
        },
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            Threading::{
                CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess,
                InitializeProcThreadAttributeList, OpenProcess, OpenProcessToken,
                UpdateProcThreadAttribute, CREATE_NEW_CONSOLE, EXTENDED_STARTUPINFO_PRESENT,
                LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_CREATE_PROCESS,
                PROCESS_DUP_HANDLE, PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION,
                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, STARTUPINFOEXW,
            },
        },
        UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_NORMAL},
    },
};
use windows_service::{
    service::{ServiceAccess, ServiceState},
    service_manager::{ServiceManager, ServiceManagerAccess},
};

fn str_to_pwstr(s: &str) -> PWSTR {
    let mut wide: Vec<u16> = s.encode_utf16().collect();
    wide.push(0);
    PWSTR(wide.as_mut_ptr())
}

fn enable_se_debug_privilege() -> Result<(), windows::core::Error> {
    unsafe {
        // Retrieve current process's token
        let mut token_handle = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token_handle,
        )?;

        // Retrieve LUID for SeDebugPrivilege
        let mut luid = LUID::default();
        LookupPrivilegeValueW(PCWSTR::null(), w!("SeDebugPrivilege"), &mut luid)?;

        // Prepare privileges for enable SeDebugPrivilege for token
        let token_privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        // Adjust token's privileges to enable SeDebugPrivilege
        AdjustTokenPrivileges(
            token_handle,
            false,
            Some(&token_privileges),
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        )?;

        CloseHandle(token_handle)?;
    }
    Ok(())
}

fn parse_process_name(exe_file: &[u16]) -> String {
    let null_pos = exe_file.iter().position(|&c| c == 0).unwrap_or(exe_file.len());
    String::from_utf16_lossy(&exe_file[..null_pos])
}

fn get_trusted_installer_pid() -> Result<u32, windows::core::Error> {
    unsafe {
        // Create a snapshot of currently running processes
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
           Ok(handle) => handle,
           Err(e) => {
               return Err(e)
           }
        };

        let mut proc_entry = PROCESSENTRY32W::default();
        proc_entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        // Get first process
        if Process32FirstW(snapshot, &mut proc_entry).is_err() {
            let _ = CloseHandle(snapshot);
            return Err(windows::core::Error::from_win32())
        }

        // Loop until if it finds a TrustedInstaller.exe process
        loop {
            if parse_process_name(&proc_entry.szExeFile).eq_ignore_ascii_case("TrustedInstaller.exe") {
                let _ = CloseHandle(snapshot);
                return Ok(proc_entry.th32ProcessID);
            }
            if Process32NextW(snapshot, &mut proc_entry).is_err() {
                let _ = CloseHandle(snapshot);
                return Err(windows::core::Error::from_win32());
            }
        }
    }
}

fn is_elevated() -> Result<bool, windows::core::Error> {
    unsafe {
        // Retrieve current process's token
        let mut token_handle = HANDLE::default();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &mut token_handle,
        ).is_err() {
            return Err(windows::core::Error::from_win32());
        }

        let mut token_elevation: TOKEN_ELEVATION = core::mem::zeroed();
        let mut return_length = 0;

        // Retrieve elevation token
        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut token_elevation as *mut _ as *mut c_void),
            core::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        let _ = CloseHandle(token_handle);

        // Return result
        match result {
            Ok(_) => Ok(token_elevation.TokenIsElevated != 0),
            Err(e) => {
                Err(e)
            }
        }
    }
}

#[derive(Debug)]
enum ElevateError {
    CurrentExe(std::io::Error),
    CurrentDir(std::io::Error),
    Execute(windows::core::Error)
}

impl fmt::Display for ElevateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CurrentExe(e) => write!(f, "Could not query current executable's path: {}", e),
            Self::CurrentDir(e) => write!(f, "Could not query current executable's running directory: {}", e),
            ElevateError::Execute(e) => write!(f, "ShellExecuteW failed to elevate process: {}", e)
        }
    }
}

fn elevate() -> Result<(), ElevateError> {
    unsafe {
        // Get current process's launching options
        let exe_path = match std::env::current_exe() {
            Ok(path) => path,
            Err(e) => {
                return Err(ElevateError::CurrentExe(e));
            }
        };
        let args: Vec<String> = std::env::args().skip(1).collect();
        let current_dir = match std::env::current_dir() {
             Ok(path) => path,
             Err(e) => {
                return Err(ElevateError::CurrentDir(e))
             }
        };

        // Run a new process using `runas` command
        let result = ShellExecuteW(
            Some(HWND::default()),
            w!("runas"),
            &HSTRING::from(exe_path.as_path()),
            &HSTRING::from(&args.join(" ")),
            &HSTRING::from(current_dir.as_path()),
            SW_NORMAL,
        );

        // Exit current process
        if (result.0 as isize) > 32 {
            std::process::exit(0);
        } else {
            return Err(ElevateError::Execute(windows::core::Error::from_win32()));
        }
    }
}

fn create_ppid_spoofed_process(ppid: u32, cmd: String) -> Result<PROCESS_INFORMATION, windows::core::Error> {
    unsafe {
        // Open TrustedInstaller's process
        let ti_handle = match OpenProcess(
            PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
            false,
            ppid,
        ) {
            Ok(handle) if !handle.is_invalid() => handle,
            Ok(_) => {
                return Err(windows::core::Error::from_win32());
            }
            Err(e) => {
                return Err(e);
            }
        };

        // Setup StartupInfo for setting PPID
        let mut si_ex: STARTUPINFOEXW = std::mem::zeroed();
        si_ex.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let mut attr_list_size: usize = 0;

        // Get size for attribute list
        let _ = InitializeProcThreadAttributeList(None, 1, Some(0), &mut attr_list_size);
        if attr_list_size == 0 {
            let _ = CloseHandle(ti_handle);
            return Err(windows::core::Error::from_win32());
        }

        let mut attr_list_buffer = vec![0u8; attr_list_size];
        si_ex.lpAttributeList = LPPROC_THREAD_ATTRIBUTE_LIST(attr_list_buffer.as_mut_ptr() as *mut c_void);

        // Initalize attribute list
        if InitializeProcThreadAttributeList(
            Some(si_ex.lpAttributeList), 
            1, 
            Some(0), 
            &mut attr_list_size
        ).is_err() {
            let _ = CloseHandle(ti_handle);
            return Err(windows::core::Error::from_win32());
        }

        // Update attribute list with parent process
        let parent_handle_ptr: *const c_void = &ti_handle as *const _ as *const c_void;
        if UpdateProcThreadAttribute(
            si_ex.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
            Some(parent_handle_ptr),
            std::mem::size_of::<HANDLE>(),
            None,
            None,
        ).is_err() {
            DeleteProcThreadAttributeList(si_ex.lpAttributeList);
            let _ = CloseHandle(ti_handle);
            return Err(windows::core::Error::from_win32());
        }

        // Create new process with PPID spoofed
        if CreateProcessW(
            None, 
            Some(str_to_pwstr(&cmd)),
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, 
            None,
            None,
            &mut si_ex.StartupInfo,
            &mut pi,
        ).is_err() {
            return Err(windows::core::Error::from_win32());
        }

        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(pi.hThread);

        DeleteProcThreadAttributeList(si_ex.lpAttributeList);
        let _ = CloseHandle(ti_handle);

        return Ok(pi)
    }
}

#[derive(Debug)]
enum RunAsTrustedInstallerError {
    Win32Error(windows::core::Error),
    ServiceManagerError(windows_service::Error),
    TimedOut
}

impl fmt::Display for RunAsTrustedInstallerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Win32Error(e) => write!(f, "Error while calling Win32 API: {}", e),
            Self::ServiceManagerError(e) => write!(f, "Error while accessing service manager: {}", e),
            Self::TimedOut => write!(f, "Timed out while getting TrustedInstaller's PID")
        }
    }
}

fn run_as_trusted_installer(cmd: String) -> Result<PROCESS_INFORMATION, RunAsTrustedInstallerError> {
    if let Err(e) = enable_se_debug_privilege() {
        return Err(RunAsTrustedInstallerError::Win32Error(e))
    }

    // Connect to service manager
    let manager = match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) {
        Ok(s) => s,
        Err(e) => {
            return Err(RunAsTrustedInstallerError::ServiceManagerError(e));
        }
    };

    // Open TrustedInstaller service
    let service = match manager.open_service("TrustedInstaller", ServiceAccess::QUERY_STATUS | ServiceAccess::START) {
        Ok(s) => s,
        Err(e) => {
            return Err(RunAsTrustedInstallerError::ServiceManagerError(e));
        }
    };

    // Query status of the service
    let service_status = match service.query_status() {
        Ok(s) => s,
        Err(e) => {
            return Err(RunAsTrustedInstallerError::ServiceManagerError(e));
        }
    };

    if service_status.current_state != ServiceState::Running {
        if let Err(e) = service.start(&[] as &[&str]) {
            return Err(RunAsTrustedInstallerError::ServiceManagerError(e));
        }
    } else {
    }

    // Loop until it finds the PID of TrustedInstaller
    let start = std::time::Instant::now();
    let ti_pid: u32 = loop {
        // Time out if it gets longer than 10 seconds
        if start.elapsed().as_secs() > 10 {
            return Err(RunAsTrustedInstallerError::TimedOut)
        }
        if let Ok(pid) = get_trusted_installer_pid() { break pid; }
    };

    match create_ppid_spoofed_process(ti_pid, cmd) {
        Ok(pi) => return Ok(pi),
        Err(e) => return Err(RunAsTrustedInstallerError::Win32Error(e))
    }
}

fn main() {
    if !is_elevated().expect("Could not check if process is elevated") {
        if let Err(e) = elevate() {
            println!("Could not run a new process with elevated privileges: {}", e);
            std::process::exit(1)
        }
        std::process::exit(0)
    }
    println!("Running with elevated privileges.");

    let mut command_line: String = "cmd".to_string();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.is_empty() { command_line = args.join(" "); }
    let _ = run_as_trusted_installer(command_line);

    // println!("Press Enter to exit...");
    // let mut input = String::new();
    // let _ = std::io::stdin().read_line(&mut input);
}
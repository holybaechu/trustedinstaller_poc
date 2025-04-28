use std::ffi::c_void;
use windows::{
    core::{w, Error, HSTRING, PCWSTR, PWSTR},
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

fn str_to_pcwstr(s: &str) -> PCWSTR {
    PCWSTR(HSTRING::from(s).as_ptr())
}

fn enable_se_debug_privilege() -> Result<(), Error> {
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
        if let Err(e) = AdjustTokenPrivileges(
            token_handle,
            false,
            Some(&token_privileges),
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        ) {
            return Err(e)
        }

        CloseHandle(token_handle)?;
    }
    Ok(())
}

fn parse_process_name(exe_file: &[u16]) -> String {
    let null_pos = exe_file.iter().position(|&c| c == 0).unwrap_or(exe_file.len());
    String::from_utf16_lossy(&exe_file[..null_pos])
}

fn get_trusted_installer_pid() -> Option<u32> {
    unsafe {
        // Create a snapshot of currently running processes
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
           Ok(handle) => handle,
           Err(e) => {
               eprintln!("Failed to create toolhelp snapshot: {}", e);
               return None;
           }
        };

        let mut proc_entry = PROCESSENTRY32W::default();
        proc_entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        // Get first process
        if Process32FirstW(snapshot, &mut proc_entry).is_err() {
            eprintln!("Failed to get first process: {}", Error::from_win32());
            let _ = CloseHandle(snapshot);
            return None;
        }

        // Loop until if it finds a TrustedInstaller.exe process
        loop {
            if parse_process_name(&proc_entry.szExeFile).eq_ignore_ascii_case("TrustedInstaller.exe") {
                let _ = CloseHandle(snapshot);
                return Some(proc_entry.th32ProcessID);
            }
            if Process32NextW(snapshot, &mut proc_entry).is_err() {
                if Error::from_win32().code() != windows::Win32::Foundation::ERROR_NO_MORE_FILES.to_hresult() {
                    eprintln!("Failed to get next process: {}", Error::from_win32());
                }
                let _ = CloseHandle(snapshot);
                return None;
            }
        }
    }
}

fn is_elevated() -> bool {
    unsafe {
        // Retrieve current process's token
        let mut token_handle = HANDLE::default();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &mut token_handle,
        )
        .is_err()
        {
            eprintln!("is_elevated: Failed to open process token: {}", Error::from_win32());
            return false;
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
            Ok(_) => token_elevation.TokenIsElevated != 0,
            Err(e) => {
                eprintln!("is_elevated: Failed to get token information: {}", e);
                false
            }
        }
    }
}

fn elevate() {
    unsafe {
        // Get current process's launching options
        let exe_path = match std::env::current_exe() {
            Ok(path) => path,
            Err(e) => {
                eprintln!("Failed to get current executable path: {}", e);
                std::process::exit(1);
            }
        };
        let args: Vec<String> = std::env::args().skip(1).collect();
        let current_dir = match std::env::current_dir() {
             Ok(path) => path,
             Err(e) => {
                eprintln!("Failed to get current directory: {}. Exiting.", e);
                std::process::exit(1);
             }
        };

        // Run a new process using `runas` command
        let result = ShellExecuteW(
            Some(HWND::default()),
            w!("runas"),
            str_to_pcwstr(exe_path.to_str().expect("Couldn't convert exe_path to &str")),
            str_to_pcwstr(&args.join(" ")),
            str_to_pcwstr(current_dir.to_str().expect("Couldn't convert current_dir to &str")),
            SW_NORMAL,
        );

        // Exit current process
        if (result.0 as isize) > 32 {
            std::process::exit(0);
        } else {
            eprintln!(
                "ShellExecuteW failed to elevate process. Error: {}",
                Error::from_win32()
            );
            std::process::exit(1);
        }
    }
}

fn main() {
    if !is_elevated() {
        elevate();

        eprintln!("Elevation failed or was cancelled.");
        return; 
    }
    println!("Running with elevated privileges.");

    if let Err(e) = enable_se_debug_privilege() {
        eprintln!("Failed to enable SeDebugPrivilege: {}", e);
    } else {
        println!("SeDebugPrivilege enabled successfully.");
    }

    // Connect to service manager
    let manager = match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)  {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Failed to connect to Service Manager: {}", e);
            return;
        }
    };

    // Open TrustedInstaller service
    let service = match manager.open_service("TrustedInstaller", ServiceAccess::QUERY_STATUS | ServiceAccess::START) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to open TrustedInstaller service: {}", e);
            return;
        }
    };

    // Query status of the service
    let service_status = match service.query_status() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to query TrustedInstaller service status: {}", e);
            return;
        }
    };

    if service_status.current_state != ServiceState::Running {
        println!("TrustedInstaller service is not running, attempting to start...");
        if let Err(e) = service.start(&[] as &[&str]) {
            eprintln!("Failed to start TrustedInstaller service: {}", e);
        }
    } else {
        println!("TrustedInstaller service is already running.");
    }

    // Loop until it finds the PID of TrustedInstaller
    println!("Waiting for TrustedInstaller PID...");
    let start = std::time::Instant::now();
    let ti_pid: u32 = loop {
        // Time out if it gets longer than 10 seconds
        if start.elapsed().as_secs() > 10 {
            eprintln!("Timed out waiting for TrustedInstaller PID.");
            return;
        }
        if let Some(pid) = get_trusted_installer_pid() { break pid; }
    };
    println!("Found TrustedInstaller PID: {}", ti_pid);

    // PPID Spoofing
    unsafe {
        // Open TrustedInstaller's process
        let ti_handle = match OpenProcess(
            PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
            false,
            ti_pid,
        ) {
            Ok(handle) if !handle.is_invalid() => handle,
            Ok(_) => {
                 eprintln!("OpenProcess succeeded but returned an invalid handle for PID: {}. Last error: {}", ti_pid, Error::from_win32());
                 return;
            }
            Err(e) => {
                eprintln!(
                    "Failed to open TrustedInstaller process (PID: {}): {}",
                    ti_pid, e
                );
                return;
            }
        };
        println!("Successfully opened handle to TrustedInstaller process.");

        // Setup StartupInfo for setting PPID
        let mut si_ex: STARTUPINFOEXW = std::mem::zeroed();
        si_ex.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let mut attr_list_size: usize = 0;

        // Get size for attribute list
        let _ = InitializeProcThreadAttributeList(None, 1, Some(0), &mut attr_list_size);
        if attr_list_size == 0 {
             eprintln!("Failed to get size for attribute list. Error: {}", Error::from_win32());
             let _ = CloseHandle(ti_handle);
             return;
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
            eprintln!("Failed to initialize attribute list. Error: {}", Error::from_win32());
            let _ = CloseHandle(ti_handle);
            return;
        }
        println!("Attribute list initialized.");

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
             eprintln!("Failed to update attribute list with parent process. Error: {}", Error::from_win32());
             DeleteProcThreadAttributeList(si_ex.lpAttributeList);
             let _ = CloseHandle(ti_handle);
             return;
        }
        println!("Attribute list updated with parent process.");
       
        let mut command_line: String = "cmd".to_string();
        let args: Vec<String> = std::env::args().skip(1).collect();
        if !args.is_empty() { command_line = args.join(" "); }

        // Create new process with PPID spoofed
        if CreateProcessW(
            None, 
            Some(str_to_pwstr(&command_line)),
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, 
            None,
            None,
            &mut si_ex.StartupInfo,
            &mut pi,
        ).is_err() {
            eprintln!("CreateProcessW failed! Error: {}", Error::from_win32());
        }

        println!(
            "CreateProcessW succeeded. New process PID: {}, TID: {}",
            pi.dwProcessId, pi.dwThreadId
        );

        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(pi.hThread);
        println!("Child process handles closed.");

        DeleteProcThreadAttributeList(si_ex.lpAttributeList);
        let _ = CloseHandle(ti_handle);
        println!("Cleaned up attribute list and parent process handle.");
    }

    // println!("Press Enter to exit...");
    // let mut input = String::new();
    // let _ = std::io::stdin().read_line(&mut input);
}
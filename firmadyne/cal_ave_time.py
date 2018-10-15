import sys
import getopt

def main():
    loop_times = 48
    total_time = 0
    sys_time = 0
    tlb_time = 0
    rest_time = 0
    syscall_count = 0 
    user_syscall_count = 0
    handle_addr = 0
    handle_state = 0
    user_syscall = 0
    full_store_page = 0
    full_restore_page = 0
    user_store_page = 0
    user_restore_page = 0
    full_snap_time = 0
    user_snap_time = 0
    snap_time = 0 #full system
    fi = open("time_result", "r")
    real_count = 0;
    ''' 
    for i in range(0, loop_times):
        line = fi.readline()
        str = line.split(':', 5)
        if(float(str[4]) > 0):
            total_time += float(str[0])
            sys_time += float(str[1])
            tlb_time += float(str[2])
            snap_time += float(str[3])
            rest_time += float(str[4])
            syscall_count += float(str[5])
            real_count+=1
        
    fi.close()
    loop_times = real_count
    print total_time/loop_times*1000, sys_time/loop_times*1000, tlb_time/loop_times*1000, snap_time/loop_times*1000, rest_time/loop_times*1000, syscall_count/loop_times             
    '''
#our system
    for i in range(0, loop_times):
        line = fi.readline()
        str = line.split(':', 13)
        total_time += float(str[0])
        sys_time += float(str[1])
        full_store_page += float(str[2])
        full_restore_page += float(str[3])
        user_store_page += float(str[4])
        user_restore_page += float(str[5])
        handle_state+= float(str[6])
        handle_addr += float(str[7])
        rest_time += float(str[8])
        syscall_count += int(str[9])
        user_syscall_count += int(str[10])
        user_syscall+= float(str[11])
        full_snap_time = full_store_page + full_restore_page
        user_snap_time =user_store_page + user_restore_page
    fi.close()
    
    print total_time/loop_times*1000, sys_time/loop_times*1000,  syscall_count/loop_times,  full_snap_time/loop_times*1000, (user_snap_time/loop_times*1000) , handle_state/loop_times*1000, handle_addr/loop_times*1000, rest_time/loop_times*1000, user_syscall/loop_times*1000, (user_syscall_count/loop_times)             
  
if __name__ == "__main__":
    main()
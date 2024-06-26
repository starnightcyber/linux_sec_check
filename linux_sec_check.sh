#!/usr/bin/env bash
# Global Settings
VER="v0.1"
dash_line="--------------------------------------------------------------------------------------------"
# 构造文件名
ipaddress=$(ip address | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+(?=\/2)' | head -n 1)
filename=$ipaddress'_'$(hostname)'_'$(whoami)'_'$(date "+%Y-%m-%d_%H:%M:%S")'.log'
# 操作系统
OS='None'
# check no.
index=-1
# set to default path: /var/www/
webpath='/var/www/'
# depth=true，深入获取信息
depth="false"
risky=""

# 文件上传企业微信, webhook地址
url="https://qyapi.weixin.qq.com/cgi-bin/webhook"
key="your-wechat-webhook-key"
header="'Content-Type:application/json'"

# Green indicates passed/OK.
print_green() {
  echo -e "\033[32m[+]$1 \033[0m"
  echo -e "$1" >>"$filename"
}
# Red indicates risk/fail.
print_red() {
  echo -e "\033[31m$1 \033[0m"
  echo -e "$1" >>"$filename"
  risky="${risky}\n$1"
}
# Title/Item print.
print_blue() {
  echo -e "\033[34m[*]$1 \033[0m"
  echo -e "$1" >>"$filename"
}
# Normal print.
print_info() {
  echo -e "$1" | tee -a "$filename"
}
print_dot_line() {
  echo -e "$dash_line"
  echo -e "$dash_line" >>"$filename"
}
print_newline() {
  echo "" | tee -a "$filename"
}

# Function to center a string within a given width
center() {
  local str="$1"
  local width="$2"
  local len=${#str}
  local padding=$(((width - len) / 2))
  printf "%*s" $((padding + len)) "$str"
  printf "%*s" $((width - padding - len)) ""
}

# Function to format table cells with fixed width
format_cell() {
  local value="$1"
  local width="$2"
  printf "%-${width}s" "$value"
}

print_script_info() {
  print_blue " ======================================================================================= "
  print_blue " \ Linux Emergency Response/Information Gathering/Vulnerability Detection Script V0.1 /  "
  print_blue " ======================================================================================= "
  print_blue " # System Support: Centos、Debian                                                      # "
  print_blue " # Author: https://github.com/al0ne                                                    # "
  print_blue " # Modify by: https://github.com/starnightcyber/linux_sec_check                        # "
  print_blue " # Update: 2024-04 ~ 2024-06                                                           # "
  print_blue " # Refer:                                                                              # "
  print_blue " #   0.LinuxCheck https://github.com/al0ne/LinuxCheck                                  # "
  print_blue " #   1.Gscan https://github.com/grayddq/GScan                                          # "
  print_blue " #   2.Lynis https://github.com/CISOfy/lynis                                           # "
  print_blue " ======================================================================================= "
  print_newline
  script_name=$(basename "$0")
  print_blue "The running script is $script_name"
}

basic_run_check() {
  index=$(($index + 1))
  print_blue "############ $index.校验系统 & 权限（仅支持 Debian/Ubuntu，且需 root 权限运行） ############"
  # 验证是否为root权限
  if [ $UID -ne 0 ]; then
    print_red "请使用root权限运行!"
    exit 1
  else
    print_green "当前为root权限"
  fi
  # 验证操作系统是debian系还是centos
  if [ -e "/etc/os-release" ]; then
    source /etc/os-release
    case ${ID} in
    "debian" | "ubuntu" | "devuan")
      OS='Debian'
      ;;
    "centos" | "rhel fedora" | "rhel")
      OS='Centos'
      ;;
    *) ;;
    esac
  fi
  # 补偿验证措施
  if [ $OS = 'None' ]; then
    if command -v apt-get >/dev/null 2>&1; then
      OS='Debian'
    elif command -v yum >/dev/null 2>&1; then
      OS='Centos'
    else
      print_red "不支持这个系统"
      print_red "Exit ..."
      exit 1
    fi
  fi
  print_green "OS:$OS"
  print_green "运行环境检测通过"
  print_newline
}

cpu_use() {
  header=("CPU Core" "Usage %" "Idle %")
  divider="---------------|---------------|---------------"
  printf "%s|%s|%s\n" "$(center "${header[0]}" 15)" "$(center "${header[1]}" 15)" "$(center "${header[2]}" 15)"
  printf "%s\n" "$divider"
  # 读取 CPU 数据前的延迟
  sleep_duration=0.1
  # 第一次读取 /proc/stat 并获取初始值
  read prev_idle prev_total < <(awk '/^cpu /{print $5, $2+$3+$4+$5+$6+$7+$8+$9+$10+$11}' /proc/stat)
  sleep $sleep_duration
  # 第二次读取 /proc/stat 并获取新值
  read idle total < <(awk '/^cpu /{print $5, $2+$3+$4+$5+$6+$7+$8+$9+$10+$11}' /proc/stat)
  # 计算差异和 CPU 使用率
  idle_diff=$((idle - prev_idle))
  total_diff=$((total - prev_total))
  usage=$(awk -v total_diff="$total_diff" -v idle_diff="$idle_diff" 'BEGIN {printf "%.2f", (100 * (total_diff - idle_diff) / total_diff)}')
  idle_rate=$(awk -v idle_diff="$idle_diff" -v total_diff="$total_diff" 'BEGIN {printf "%.2f", (100 * idle_diff / total_diff)}')
  # 对每个 CPU 核心进行相同的操作
  cpu_count=$(grep -c '^processor' /proc/cpuinfo)
  for ((i = 0; i < cpu_count; i++)); do
    read prev_idle prev_total < <(awk -v cpu_id="$i" '/^cpu[0-9]+/{if (NR == cpu_id+2) print $5, $2+$3+$4+$5+$6+$7+$8+$9+$10+$11}' /proc/stat)
    sleep $sleep_duration
    read idle total < <(awk -v cpu_id="$i" '/^cpu[0-9]+/{if (NR == cpu_id+2) print $5, $2+$3+$4+$5+$6+$7+$8+$9+$10+$11}' /proc/stat)
    idle_diff=$((idle - prev_idle))
    total_diff=$((total - prev_total))
    usage=$(awk -v total_diff="$total_diff" -v idle_diff="$idle_diff" 'BEGIN {printf "%.2f", (100 * (total_diff - idle_diff) / total_diff)}')
    idle_rate=$(awk -v idle_diff="$idle_diff" -v total_diff="$total_diff" 'BEGIN {printf "%.2f", (100 * idle_diff / total_diff)}')
    printf "%s|%s|%s\n" "$(center "CPU$i" 15)" "$(center "$usage%" 15)" "$(center "$idle_rate%" 15)"
  done
}

basic_info_collect() {
  index=$(($index + 1))
  print_blue "############ $index.基础信息采集 ############"
  print_blue "『系统信息』"
  #主机名
  Hostname="【 Hostname 】: $(hostname -s)"
  print_info "$Hostname"
  #ipaddress
  ipaddress="【  IP Addr 】: $(ip addr show eth0 | grep "inet " | awk '{print $2}' | cut -d/ -f1)"
  print_info "$ipaddress"
  #当前用户
  USER="【   USER   】: $(whoami)"
  print_info "$USER"
  #版本信息
  OS_ver="【OS Version】: $(
    if [[ "${OS,,}" == 'centos' ]]; then
      cat /etc/redhat-release
    else
      cat /etc/issue.net
    fi
  )"
  print_info "$OS_ver"
  #uptime
  Uptime="【  Uptime  】: $(uptime | awk -F ',' '{print $1}')"
  print_info "$Uptime"
  #cpu核心
  CPU_Core="【 CPU Core 】: $(cat /proc/cpuinfo | grep 'processor' | sort | uniq | wc -l)"
  print_info "$CPU_Core"
  #cpu信息
  CPU_INFO="【 CPU Info 】: $(cat /proc/cpuinfo | grep "model name" | awk -F ':' '{print $2}' | head -n 1)"
  print_info "$CPU_INFO"
  #系统负载
  Load="【 Load Avg 】: $(uptime | awk '{print $9" "$10" "$11" "$12" "$13}')"
  print_info "$Load"
  #服务器SN
  SN="【Serial No.】: $(dmidecode -t1 | grep "Serial Number" | awk -F ':' '{print $2}')"
  print_info "$SN"
  #登陆用户
  Login_User="【Login User】: $dash_line\n $(who | awk '{print "\t\t| " $0}')"
  print_info "$Login_User"
  print_newline
  print_blue "『CPU使用率』"
  print_info "$(cpu_use)"
  print_newline
  #内存占用
  print_blue "『内存使用』"
  print_info "$(free -mh)"
  print_newline
  #磁盘空间
  print_blue "『磁盘空间使用情况』"
  print_info "$(df -mh)"
  print_newline
  #硬盘挂载
  print_blue "『硬盘挂载』"
  print_info "$(cat /etc/fstab | grep -v '#' | awk '{print $1,$2,$3}')"
  print_newline
  #安装软件
  print_blue "『系统常见软件安装』"
  cmdline=(
    "which node"
    "which nodejs"
    "which bind"
    "which tomcat"
    "which curl"
    "which wget"
    "which mysql"
    "which redis"
    "which ssserver"
    "which vsftpd"
    "which apache"
    "which apache2"
    "which nginx"
    "which mongodb"
    "which docker"
    "which tftp"
    "which psql"
    "which kafka"
  )
  # Print table header
  print_info "$dash_line"
  print_info "| $(format_cell 'Software Name' 15) | $(format_cell 'Path' 35) | $(format_cell 'MD5' 32) |"
  print_info "$dash_line"
  for prog in "${cmdline[@]}"; do
    soft=$($prog 2>/dev/null)
    if [ "$soft" ]; then
      soft_name=$(basename "$soft")
      md5_value=$(md5sum "$soft" | awk '{print $1}')
      print_info "| $(format_cell "$soft_name" 15) | $(format_cell "$soft" 35) | $(format_cell "$md5_value" 32) |"
    fi
  done
  print_dot_line
  print_newline
}

process_check() {
  index=$(($index + 1))
  print_blue "############ $index.进程|软件检查 ############"
  # CPU占用 TOP 10
  print_blue "『CPU占用 Top10』"
  ps aux | sort -nrk 3,3 | head -n 10 | awk 'BEGIN {
      print " USER       PID   %CPU   %MEM   TIME      COMMAND"
      print "------     -----   ----  ----  -------    -------"
  } {
      printf "%-10s %-7s %-5s %-5s %-10s %s\n", $1, $2, $3, $4, $10, $11
  }' | tee -a "$filename"
  print_newline
  print_blue "『内存占用 Top10』"
  ps aux | sort -nrk 4,4 | head -n 10 | awk 'BEGIN {
      print "USER        PID    %CPU    %MEM   TIME    COMMAND"
      print "----       -----   ----    ----  ------   -------"
  } {
      printf "%-10s %-7s %-7s %-5s %-8s %s\n", $1, $2, $3, $4, $10, $11
  }' | tee -a "$filename"
  print_newline
  print_blue "『木马/挖矿检查』"
  # 列出当前系统中的所有进程，并筛选出常见的木马/挖矿进程名称
  ps aux | grep -E "xmrig|xmr-stak|minerd|cpuminer|kdevtmpfsi|kinsing" | grep -v 'grep' | awk 'BEGIN {
      print " USER       PID   %CPU   %MEM   TIME      COMMAND"
      print "------     -----   ----  ----  -------    -------"
  } {
      printf "%-10s %-7s %-5s %-5s %-10s %s\n", $1, $2, $3, $4, $10, $11
  }' | tee -a "$filename"
  print_newline
}

ifconfig_info() {
  # 运行 ifconfig -a 命令
  ifconfig_output=$(ifconfig -a)
  # 提取关键信息并格式化输出
  echo "$ifconfig_output" | awk '
  BEGIN {
      FS=" ";
      OFS="\t";
      print "Interface", "IPv4 Address", "Netmask", "Broadcast", "IPv6 Address", "MAC Address";
      print "---------", "------------", "-------", "---------", "------------", "------------";
  }
  /^([a-zA-Z0-9]+): / {
      if (interface) {
          print interface, (ipv4 == "" ? "N/A" : ipv4), (netmask == "" ? "N/A" : netmask), (broadcast == "" ? "N/A" : broadcast), (ipv6 == "" ? "N/A" : ipv6), (mac == "" ? "N/A" : mac);
      }
      interface = $1;
      gsub(":", "", interface);
      ipv4 = "";
      netmask = "";
      broadcast = "";
      ipv6 = "";
      mac = "";
  }
  /inet / {
      ipv4 = $2;
      netmask = $4;
      broadcast = $6;
  }
  /inet6 / {
      ipv6 = $2;
  }
  /ether / {
      mac = $2;
  }
  END {
      if (interface) {
          print interface, (ipv4 == "" ? "N/A" : ipv4), (netmask == "" ? "N/A" : netmask), (broadcast == "" ? "N/A" : broadcast), (ipv6 == "" ? "N/A" : ipv6), (mac == "" ? "N/A" : mac);
      }
  }' | column -t -s $'\t'
}

network_check() {
  index=$(($index + 1))
  print_blue "############ $index.网络/流量检查 ############"
  # 网卡信息
  print_blue "『网卡信息』"
  print_info "$(ifconfig_info)"
  print_newline
  # 网卡混杂模式
  print_blue "『网卡混杂模式』"
  if ip link | grep PROMISC >/dev/null 2>&1; then
    print_red "网卡存在混杂模式！"
  else
    print_green "网卡不存在混杂模式"
  fi
  print_newline
  # 路由转发
  print_blue "『路由转发』"
  ip_forward=$(more /proc/sys/net/ipv4/ip_forward | awk -F: '{if ($1==1) print "1"}')
  if [ -n "$ip_forward" ]; then
    print_red "/proc/sys/net/ipv4/ip_forward 已开启路由转发"
  else
    print_green "未开启路由转发"
  fi
  print_newline
  # 对外开放高危通用服务：端口 & 服务名请自行补充
  print_blue "『对外开放高危通用服务』"
  print_info "$(netstat -tulpen | grep -v '127.0.0.1\|::1' | grep tcp | grep -iE ':(21|22|23|25|110|143|389|1433|1521|2049|3306|3389|5432|6379|9200|9300|11211|27017)\s|(FTP|SSHD|Telnet|SMTP|DNS|POP3|IMAP|MySQL|Postgre|Redis|MongoDB|Oracle|RDP|Elasticsearch|Memcached)')"
  print_newline
  # DNS
  print_blue "『DNS 配置』"
  print_info "$(grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' /etc/resolv.conf)"
  print_newline
  # 路由表
  print_blue "『路由表』"
  print_info "$(/sbin/route -nee)"
  print_newline
  # 连接状态
  print_blue "『TCP连接状态统计计数』"
  netstat -n | awk '/^tcp/ {++S[$NF]} END {
    printf "%-20s%-20s\n", "State", "Count"
    printf "%-20s%-20s\n", "-----------", "-----"
    for(a in S) printf "%-20s%-20d\n", a, S[a]
  }' | tee -a "$filename"
  print_newline
}

user_crontask() {
  # Print the table headers
  printf "%-20s | %-50s\n" "User" "Crontab Task"
  printf "%-20s | %-50s\n" "--------------------" "--------------------------------------------------"
  # Iterate over each user in /etc/passwd
  while IFS=: read -r username _; do
    crontab_tasks=$(crontab -l -u "$username" 2>/dev/null)
    if [ -n "$crontab_tasks" ]; then
      # Split crontab tasks into array
      IFS=$'\n' read -rd '' -a tasks <<<"$crontab_tasks"
      first_task=true
      for task in "${tasks[@]}"; do
        [[ "$task" =~ ^#.*$ ]] && continue
        if [ "$first_task" = true ]; then
          printf "%-20s | %-50s\n" "$username" "$task"
          first_task=false
        else
          printf "%-20s | %-50s\n" "" "$task"
        fi
      done
      printf "%-20s | %-50s\n" "--------------------" "--------------------------------------------------"
    fi
  done </etc/passwd
}

crontab_check() {
  index=$(($index + 1))
  print_blue "############ $index.任务计划检查 ############"
  print_blue "『user crontasks』"
  print_info "$(user_crontask)"
  print_newline
  # crontab 后门检查
  print_blue "『Crontab Backdoor』"
  print_info "$(grep -Er '(?:useradd|groupadd|chattr)|(?:wget\s|curl\s|tftp\s\-i|scp\s|sftp\s)|(tftp\s\-i|scp\s|sftp\s|bash\s\-i|nc\s\-e|sh\s\-i|wget\s|curl\s|/dev/tcp/|/dev/udp/)' /etc/cron* /var/spool/cron/* | grep -v '#')"
  print_newline
  if [ "$depth" = "true" ]; then
    print_blue "『/etc/cron.*』"
    print_info "$(ls -alht /etc/cron.*/*)"
    print_newline
  fi
}

env_check() {
  index=$(($index + 1))
  print_blue "############ $index.环境变量检查 ############"
  # env
  print_blue "『env』"
  print_info "$(env | grep -v LS_COLORS)"
  print_newline
  # PATH
  print_blue "『PATH』"
  print_info "$(echo "$PATH")"
  print_newline
}

user_check() {
  index=$(($index + 1))
  print_blue "############ $index.用户信息检查 ############"
  print_blue "『可登陆用户』"
  print_info "$(awk -F: '$7 !~ /nologin|false$/ {print $0}' /etc/passwd)"
  print_newline
  print_blue "『/etc/passwd 文件修改日期』"
  print_info "$(stat -c %y /etc/passwd)"
  print_newline
  print_blue "『Root权限（非root）账号』"
  print_info "$(cat /etc/passwd | awk -F ':' '$3==0' | egrep -v root:)"
  print_newline
  print_blue '『sudoers(请注意NOPASSWD)』'
  print_info "$(cat /etc/sudoers | grep -v '#' | sed -e '/^$/d' | grep ALL)"
  print_newline
  print_blue "『登录信息 - w』"
  print_info "$(w)"
  print_newline
  print_blue "『登录信息 - lastlog/filter never logged in』"
  print_info "$(lastlog | grep -v "Never logged in")"
  print_newline
  print_blue "『登录记录 - 计数』"
  printf "%-20s %-8s\n" "IP Address" "Count"
  printf "%-20s %-8s\n" "-------------------" "--------"
  print_info "$(
    grep -i -a Accepted /var/log/secure /var/log/auth.* 2>/dev/null | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' |
      awk '{ip_count[$0]++}
        END {
            for (ip in ip_count) {
                printf "%-20s %-8d\n", ip, ip_count[ip]
            }
        }' | sort -k2 -nr
  )"
  print_newline
  print_blue "『登录记录 - last』"
  print_info "$(last)"
  print_newline
}

service_check() {
  index=$(($index + 1))
  print_blue "############ $index.服务状态检查 ############"
  print_blue "『正在运行的Service』"
  print_info "$(systemctl -l | grep running | awk '{print $1}' | paste -d'\t' - - - - | column -s $'\t' -t)"
  print_newline
  if [ "$depth" = "true" ]; then
    print_blue "『multi-user.target 运行级别服务』"
    print_info "$(ls -alhtR /etc/systemd/system/multi-user.target.wants)"
    print_newline
    print_blue "『用户自定义 Systemd 服务单元』"
    print_info "$(ls -alht /etc/systemd/system/*.service | grep -v 'dbus-org')"
    print_newline
  fi
}

bash_check() {
  index=$(($index + 1))
  print_blue "###### $index.Bash 配置检查 ######"
  # 查看history文件
  print_blue "『History 文件』"
  print_info "$(find /root /home -name '.*_history')"
  print_newline
  # History 危险命令
  print_blue "『History 危险命令』"
  print_info "$(find /root /home -name '.*_history' | xargs -i{} cat {} | egrep '\b(?:\d{1,3}\.){3}\d{1,3}\b|http://|https://|\bssh\b|\bscp\b|\.tar|\bwget\b|\bcurl\b|\bnc\b|\btelnet\b|\bbash\b|\bsh\b|\bchmod\b|\bchown\b|/etc/passwd|/etc/shadow|/etc/hosts|\bnmap\b|\bfrp\b|\bnfs\b|\bsshd\b|\bmodprobe\b|\blsmod\b|\bsudo\b' | egrep -v 'man\b|ag\b|cat\b|sed\b|git\b|docker\b|rm\b|touch\b|mv\b|\bapt\b|\bapt-get\b' | grep -v $script_name)"
  print_newline
  # bash反弹shell
  print_blue "『bash反弹shell』"
  print_info "$(ps -ef | grep 'bash -i' | grep -v 'grep' | awk '{print $2}' | xargs -i{} lsof -p {} | grep 'ESTAB')"
  print_newline
}

file_check() {
  index=$(($index + 1))
  print_blue "############ $index.文件检查 ############"
  print_blue "『系统文件修改时间』"
  cmdline=(
    "/sbin/ifconfig"
    "/bin/ls"
    "/bin/login"
    "/bin/netstat"
    "/usr/bin/top"
    "/bin/ps"
    "/usr/bin/find"
    "/bin/grep"
    "/etc/passwd"
    "/etc/shadow"
    "/usr/bin/curl"
    "/usr/bin/wget"
    "/root/.ssh/authorized_keys"
  )
  # 打印表头
  printf "%-35s %-25s\n" "文件路径" "    修改日期"
  printf "%s\n" "----------------------------------- -----------------------------------"
  # 遍历数组并打印每个文件的信息
  for soft in "${cmdline[@]}"; do
    if [ -e "$soft" ]; then
      mod_date=$(stat -c %y "$soft")
      printf "%-35s %-25s\n" "$soft" "$mod_date"
    else
      printf "%-35s %-25s\n" "$soft" "文件不存在"
    fi
  done
  print_newline
  # alias 别名
  print_blue "『Alias 检查』"
  print_info "$(alias | grep -v 'git')"
  print_newline
  if [ "$depth" = "true" ]; then
    # SUID
    print_blue "『SUID』"
    print_info "$(find / ! -path "/proc/*" -perm -004000 -type f 2>/dev/null | egrep -v 'snap|docker|pam_timestamp_check|unix_chkpwd|ping|mount|su|pt_chown|ssh-keysign|at|passwd|chsh|crontab|chfn|usernetctl|staprun|newgrp|chage|dhcp|helper|pkexec|top|Xorg|nvidia-modprobe|quota|login|security_authtrampoline|authopen|traceroute6|traceroute|ps|newuidmap|newgidmap')"
    print_newline
    # lsof -L1, 进程存在但文件已经没有了
    print_blue "『lsof -L1/进程存在但文件已经没有了』"
    print_info "$(lsof +L1)"
    print_newline
    # 近7天改动
    print_blue "『近七天文件改动 mtime』"
    print_info "$(find /etc /bin /lib /sbin /dev /root/ /home /tmp /var /usr ! -path "/var/log*" ! -path "/var/spool/exim4*" ! -path "/var/backups*" -mtime -7 -type f 2>/dev/null | egrep -v '\.log|cache|vim|/share/|/lib/|.zsh|.gem|\.git|LICENSE|README|/_\w+\.\w+|\blogs\b|elasticsearch|nohup|i18n' | xargs -i{} ls -alh {})"
    print_newline
    # 近7天改动
    print_blue "『近七天文件改动 ctime』"
    print_info "$(find /etc /bin /lib /sbin /dev /root/ /home /tmp /var /usr ! -path "/var/log*" ! -path "/var/spool/exim4*" ! -path "/var/backups*" -ctime -7 -type f 2>/dev/null | egrep -v '\.log|cache|vim|/share/|/lib/|.zsh|.gem|\.git|LICENSE|README|/_\w+\.\w+|\blogs\b|elasticsearch|nohup|i18n' | xargs -i{} ls -alh {})"
    print_newline
    # 黑客文件备份
    print_blue "『大文件>200MB』"
    print_info "$(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -size +200M -exec ls -alht {} + 2>/dev/null | egrep '\.gif|\.jpeg|\.jpg|\.png|\.zip|\.tar.gz|\.tgz|\.7z|\.log|\.xz|\.rar|\.bak|\.old|\.sql|\.1|\.txt|\.tar|\.db|/\w+$' | egrep -v 'ib_logfile|ibd|mysql-bin|mysql-slow|ibdata1|overlay2')"
    print_newline
    # 敏感文件
    print_blue "『敏感文件』"
    print_info "$(find / ! -path "/lib/modules*" ! -path "/usr/src*" ! -path "/snap*" ! -path "/usr/include/*" -regextype posix-extended -regex '.*sqlmap|.*msfconsole|.*\bncat|.*\bnmap|.*nikto|.*ettercap|.*tunnel\.(php|jsp|asp|py)|.*/nc\b|.*socks.(php|jsp|asp|py)|.*proxy.(php|jsp|asp|py)|.*brook.*|.*frps|.*frpc|.*aircrack|.*hydra|.*miner|.*/ew$' -type f 2>/dev/null | grep -v '/lib/python' | xargs -i{} ls -alh {})"
    print_newline
    # 可疑黑客文件
    print_blue "『可疑黑客文件』"
    print_info "$(find /root /home /opt /tmp /var/ /dev -regextype posix-extended -regex '.*wget|.*curl|.*openssl|.*mysql' -type f 2>/dev/null | xargs -i{} ls -alh {} | egrep -v '/pkgs/|/envs/')"
    print_newline
    print_blue "『...隐藏文件』"
    print_info "$(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -name ".*." 2>/dev/null)"
    print_newline
  fi
}

rootkit_check() {
  index=$(($index + 1))
  print_blue "############ $index.Rootkit检查 ############"
  # lsmod 可疑模块
  print_blue "『lsmod 可疑模块』"
  print_info "$(lsmod | egrep -v "ablk_helper|ac97_bus|acpi_power_meter|aesni_intel|ahci|ata_generic|ata_piix|auth_rpcgss|binfmt_misc|bluetooth|bnep|bnx2|bridge|cdrom|cirrus|coretemp|crc_t10dif|crc32_pclmul|crc32c_intel|crct10dif_common|crct10dif_generic|crct10dif_pclmul|cryptd|dca|dcdbas|dm_log|dm_mirror|dm_mod|dm_region_hash|drm|drm_kms_helper|drm_panel_orientation_quirks|e1000|ebtable_broute|ebtable_filter|ebtable_nat|ebtables|edac_core|ext4|fb_sys_fops|floppy|fuse|gf128mul|ghash_clmulni_intel|glue_helper|grace|i2c_algo_bit|i2c_core|i2c_piix4|i7core_edac|intel_powerclamp|ioatdma|ip_set|ip_tables|ip6_tables|ip6t_REJECT|ip6t_rpfilter|ip6table_filter|ip6table_mangle|ip6table_nat|ip6ta ble_raw|ip6table_security|ipmi_devintf|ipmi_msghandler|ipmi_si|ipmi_ssif|ipt_MASQUERADE|ipt_REJECT|iptable_filter|iptable_mangle|iptable_nat|iptable_raw|iptable_security|iTCO_vendor_support|iTCO_wdt|jbd2|joydev|kvm|kvm_intel|libahci|libata|libcrc32c|llc|lockd|lpc_ich|lrw|mbcache|megaraid_sas|mfd_core|mgag200|Module|mptbase|mptscsih|mptspi|nf_conntrack|nf_conntrack_ipv4|nf_conntrack_ipv6|nf_defrag_ipv4|nf_defrag_ipv6|nf_nat|nf_nat_ipv4|nf_nat_ipv6|nf_nat_masquerade_ipv4|nfnetlink|nfnetlink_log|nfnetlink_queue|nfs_acl|nfsd|parport|parport_pc|pata_acpi|pcspkr|ppdev|rfkill|sch_fq_codel|scsi_transport_spi|sd_mod|serio_raw|sg|shpchp|snd|snd_ac97_codec|snd_ens1371|snd_page_alloc|snd_pcm|snd_rawmidi|snd_seq|snd_seq_device|snd_seq_midi|snd_seq_midi_event|snd_timer|soundcore|sr_mod|stp|sunrpc|syscopyarea|sysfillrect|sysimgblt|tcp_lp|ttm|tun|uvcvideo|videobuf2_core|videobuf2_memops|videobuf2_vmalloc|videodev|virtio|virtio_balloon|virtio_console|virtio_net|virtio_pci|virtio_ring|virtio_scsi|vmhgfs|vmw_balloon|vmw_vmci|vmw_vsock_vmci_transport|vmware_balloon|vmwgfx|vsock|xfs|xt_CHECKSUM|xt_conntrack|xt_state|raid*|tcpbbr|btrfs|.*diag|psmouse|ufs|linear|msdos|cpuid|veth|xt_tcpudp|xfrm_user|xfrm_algo|xt_addrtype|br_netfilter|input_leds|sch_fq|ib_iser|rdma_cm|iw_cm|ib_cm|ib_core|.*scsi.*|tcp_bbr|pcbc|autofs4|multipath|hfs.*|minix|ntfs|vfat|jfs|usbcore|usb_common|ehci_hcd|uhci_hcd|ecb|crc32c_generic|button|hid|usbhid|evdev|hid_generic|overlay|xt_nat|qnx4|sb_edac|acpi_cpufreq|ixgbe|pf_ring|tcp_htcp|cfg80211|x86_pkg_temp_thermal|mei_me|mei|processor|thermal_sys|lp|enclosure|ses|ehci_pci|igb|i2c_i801|pps_core|isofs|nls_utf8|xt_REDIRECT|xt_multiport|iosf_mbi|qxl|cdc_ether|usbnet|ip6table_raw|skx_edac|intel_rapl|wmi|acpi_pad|ast|i40e|ptp|nfit|libnvdimm|bpfilter|failover")"
  print_newline
  # Rootkit 内核模块
  print_blue "『Rootkit 内核模块』"
  kernel=$(grep -E 'hide_tcp4_port|hidden_files|hide_tcp6_port|diamorphine|module_hide|module_hidden|is_invisible|hacked_getdents|hacked_kill|heroin|kernel_unlink|hide_module|find_sys_call_tbl|h4x_delete_module|h4x_getdents64|h4x_kill|h4x_tcp4_seq_show|new_getdents|old_getdents|should_hide_file_name|should_hide_task_name' </proc/kallsyms)
  if [ -n "$kernel" ]; then
    print_red "存在内核敏感函数！疑似Rootkit内核模块"
  else
    print_info "未找到内核敏感函数"
  fi
  print_newline
  # 可疑的.ko模块
  if [ "$depth" = "true" ]; then
    print_blue "『可疑的.ko模块』"
    print_info "$(find / ! -path "/proc/*" ! -path "/usr/lib/modules/*" ! -path "/lib/modules/*" ! -path "/boot/*" -regextype posix-extended -regex '.*\.ko' 2>/dev/null | xargs -i{} md5sum {})"
    print_newline
  fi
}

ssh_keys() {
  # 目标路径数组
  paths=("/root" "/home/*")
  # 打印表头
  printf "%-40s | %s\n" "Authorized Keys File Path" "Comment"
  # 遍历目录中的 authorized_keys 文件
  for path in ${paths[@]}; do
    file_path="$path/.ssh/authorized_keys"
    # 判断文件是否存在
    if [[ -f "$file_path" ]]; then
      file_printed=false
      # 读取文件中的 comment 信息，并输出表格行
      while IFS= read -r line; do
        if [[ "$line" =~ ^ssh ]]; then
          # 提取 comment 信息
          comment=$(echo "$line" | cut -d' ' -f3-)
          # 如果文件路径没有打印过，打印文件路径
          if [ "$file_printed" = false ]; then
            printf "%-40s | %s\n" "----------------------------------------" "------------------"
            printf "%-40s | %s\n" "$file_path" "$comment"
            file_printed=true
          else
            printf "%-40s | %s\n" "" "$comment"
          fi
        fi
      done <"$file_path"
      # 打印分割线
    fi
  done
  printf "%-40s | %s\n" "----------------------------------------" "------------------"
}

ssh_check() {
  index=$(($index + 1))
  print_blue "############ $index.SSH检查 ############"
  # SSH 监听 & 链接信息
  print_blue "『SSH 监听 & 链接』"
  print_info "$(lsof -i -nP | grep 'sshd')"
  print_newline
  # SSH 爆破IP
  print_blue "『SSH爆破 IPs Top10』"
  if [ "$OS" = 'Centos' ]; then
    print_info "$(
      printf "%-20s %-8s\n" "IP Address" "Attempts"
      printf "%-20s %-8s\n" "-------------------" "--------"
      grep 'Invalid user' /var/log/secure* | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' |
        awk '{ip_count[$0]++}
        END {
            for (ip in ip_count) {
                printf "%-20s %-8d\n", ip, ip_count[ip]
            }
        }' | sort -k2 -nr | head -10
    )"
  else
    print_info "$(
      printf "%-20s %-8s\n" "IP Address" "Attempts"
      printf "%-20s %-8s\n" "-------------------" "--------"
      grep 'Invalid user' /var/log/auth* | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' |
        awk '{ip_count[$0]++}
        END {
            for (ip in ip_count) {
                printf "%-20s %-8d\n", ip, ip_count[ip]
            }
        }' | sort -k2 -nr | head -10
    )"
  fi
  print_newline
  # SSHD
  print_blue "『SSHD:/usr/sbin/sshd A/M/C Time』"
  print_info "$(stat /usr/sbin/sshd | egrep 'Access|Modify|Change')"
  print_newline
  # SSH 后门配置检查
  print_blue "『SSH 后门配置』"
  if [ -e "$HOME/.ssh/config" ]; then
    print_info "$(grep LocalCommand <~/.ssh/config)"
    print_info "$(grep ProxyCommand <~/.ssh/config)"
  else
    print_green "未发现 SSH 后门配置"
  fi
  print_newline
  # SSH 后门配置检查
  print_blue "『SSH 软连接后门』"
  if ps -ef | grep -P '\s+\-oport=\d+' >/dev/null 2>&1; then
    print_info "$(ps -ef | grep -P '\s+\-oport=\d+')"
  else
    print_green "未检测到SSH软连接后门"
  fi
  print_newline
  # SSH inetd后门检查
  print_blue "『SSH inetd后门检查』"
  if [ -e "/etc/inetd.conf" ]; then
    print_info "$(grep -E '(bash -i)' </etc/inetd.conf)"
  else
    print_green "未检测到SSH inetd后门检查"
  fi
  print_newline
  # user SSH Key
  print_blue "『SSH Key』"
  print_info "$(ssh_keys)"
  print_newline
}

webshell_check() {
  index=$(($index + 1))
  print_blue "############ $index.Webshell检查 ############"
  print_blue "『PHP webshell查杀』"
  print_info "$(grep -P -i -r -l 'array_map\(|pcntl_exec\(|proc_open\(|popen\(|assert\(|phpspy|c99sh|milw0rm|eval?\(|\(gunerpress|\(base64_decoolcode|spider_bc|shell_exec\(|passthru\(|base64_decode\s?\(|gzuncompress\s?\(|gzinflate|\(\$\$\w+|call_user_func\(|call_user_func_array\(|preg_replace_callback\(|preg_replace\(|register_shutdown_function\(|register_tick_function\(|mb_ereg_replace_callback\(|filter_var\(|ob_start\(|usort\(|uksort\(|uasort\(|GzinFlate\s?\(|\$\w+\(\d+\)\.\$\w+\(\d+\)\.|\$\w+=str_replace\(|eval\/\*.*\*\/\(' $webpath --include='*.php*' --include='*.phtml')"
  print_info "$(grep -P -i -r -l '^(\xff\xd8|\x89\x50|GIF89a|GIF87a|BM|\x00\x00\x01\x00\x01)[\s\S]*<\?\s*php' $webpath --include='*.php*' --include='*.phtml')"
  print_info "$(grep -P -i -r -l '\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\/*\s]*((\$_(GET|POST|REQUEST|COOKIE)\[.{0,25})|(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\(]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25}))' $webpath --include='*.php*' --include='*.phtml')"
  print_info "$(grep -P -i -r -l '\$\s*(\w+)\s*=[\s\(\{]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25});[\s\S]{0,200}\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\s"\/*]*(\$\s*\1|((base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\("]*\$\s*\1))' $webpath --include='*.php*' --include='*.phtml')"
  print_info "$(grep -P -i -r -l '\b(filter_var|filter_var_array)\b\s*\(.*FILTER_CALLBACK[^;]*((\$_(GET|POST|REQUEST|COOKIE|SERVER)\[.{0,25})|(eval|assert|ass\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec))' $webpath --include='*.php*' --include='*.phtml')"
  print_info "$(grep -P -i -r -l "\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|include)\b\s*\(\s*(file_get_contents\s*\(\s*)?[\'\"]php:\/\/input" $webpath --include='*.php*' --include='*.phtml')"
  print_info "$(grep -P -i -r -l 'getruntime|processimpl|processbuilder|defineclass|classloader|naming.lookup|internaldofilter|elprocessor|scriptenginemanager|urlclassloader|versionhelper|registermapping|registerhandler|detecthandlermethods|\\u0063\\u006c\\u0061\\u0073\\u0073' $webpath --include='*.php*' --include='*.phtml')"
  print_info "$(grep -P -i -r -l 'phpinfo|move_uploaded_file|system|shell_exec|passthru|popen|proc_open|pcntl_exec|call_user_func|ob_start' $webpath --include='*.php*' --include='*.phtml')"
  print_info "$(grep -P -i -r -l 'array_map|uasort|uksort|array_diff_uassoc|array_diff_ukey|array_intersect_uassoc|array_intersect_ukey|array_reduce|array_filter|array_udiff|array_udiff_assoc|array_udiff_uassoc|array_uintersect|array_uintersect_assoc|array_uintersect_uassoc|array_walk|array_walk_recursive|register_shutdown_function|register_tick_function|filter_var_array|yaml_parse|sqlite_create_function|fgetc|fgets|fgetss|fpassthru|fread|file_get_contents|readfile|stream_get_contents|stream_get_line|highlight_file|show_source|file_put_contents|pfsockopen|fsockopen' $webpath --include='*.php*' --include='*.phtml')"
  print_newline
  # JSP webshell查杀
  print_blue "『JSP webshell查杀』"
  print_info "$(grep -P -i -r -l '<%@\spage\simport=[\s\S]*\\u00\d+\\u00\d+|<%@\spage\simport=[\s\S]*Runtime.getRuntime\(\).exec\(request.getParameter\(|Runtime.getRuntime\(\)' $webpath)"
  print_newline
}

poison_check() {
  index=$(($index + 1))
  print_blue "############ $index.供应链投毒检测 ############"
  print_blue "『Python2 pip 检测』"
  print_info "$(pip freeze 2>/dev/null | egrep "istrib|djanga|easyinstall|junkeldat|libpeshka|mumpy|mybiubiubiu|nmap-python|openvc|python-ftp|pythonkafka|python-mongo|python-mysql|python-mysqldb|python-openssl|python-sqlite|virtualnv|mateplotlib|request=")"
  print_newline
  print_blue "『Python3 pip 检测』"
  print_info "$(pip3 freeze 2>/dev/null | egrep "istrib|djanga|easyinstall|junkeldat|libpeshka|mumpy|mybiubiubiu|nmap-python|openvc|python-ftp|pythonkafka|python-mongo|python-mysql|python-mysqldb|python-openssl|python-sqlite|virtualnv|mateplotlib|request=")"
  print_newline
}

miner_check() {
  index=$(($index + 1))
  print_blue "############ $index.挖矿检测 ############"
  print_blue "『常规挖矿进程检测』"
  print_red "$(ps aux | egrep "systemctI|kworkerds|init10.cfg|wl.conf|crond64|watchbog|sustse|donate|proxkekman|test.conf|/var/tmp/apple|/var/tmp/big|/var/tmp/small|/var/tmp/cat|/var/tmp/dog|/var/tmp/mysql|/var/tmp/sishen|ubyx|cpu.c|tes.conf|psping|/var/tmp/java-c|pscf|cryptonight|sustes|xmrig|xmr-stak|suppoie|ririg|/var/tmp/ntpd|/var/tmp/ntp|/var/tmp/qq|/tmp/qq|/var/tmp/aa|gg1.conf|hh1.conf|apaqi|dajiba|/var/tmp/look|/var/tmp/nginx|dd1.conf|kkk1.conf|ttt1.conf|ooo1.conf|ppp1.conf|lll1.conf|yyy1.conf|1111.conf|2221.conf|dk1.conf|kd1.conf|mao1.conf|YB1.conf|2Ri1.conf|3Gu1.conf|crant|nicehash|linuxs|linuxl|Linux|crawler.weibo|stratum|gpg-daemon|jobs.flu.cc|cranberry|start.sh|watch.sh|krun.sh|killTop.sh|cpuminer|/60009|ssh_deny.sh|clean.sh|\./over|mrx1|redisscan|ebscan|barad_agent|\.sr0|clay|udevs|\.sshd|/tmp/init|xmr|xig|ddgs|minerd|hashvault|geqn|\.kthreadd|httpdz|pastebin.com|sobot.com|kerbero|2t3ik|ddgs|qW3xt|ztctb" | egrep -v "grep|$script_name")"
  print_red "$(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -regextype posix-extended -regex '.*systemctI|.*kworkerds|.*init10.cfg|.*wl.conf|.*crond64|.*watchbog|.*sustse|.*donate|.*proxkekman|.*cryptonight|.*sustes|.*xmrig|.*xmr-stak|.*suppoie|.*ririg|gg1.conf|.*cpuminer|.*xmr|.*xig|.*ddgs|.*minerd|.*hashvault|\.kthreadd|.*httpdz|.*kerbero|.*2t3ik|.*qW3xt|.*ztctb|.*miner.sh' -type f 2>/dev/null)"
  print_newline
  print_blue "『Ntpclient 挖矿木马检测』"
  print_red "$(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/boot/*" -regextype posix-extended -regex 'ntpclient|Mozz' 2>/dev/null)"
  print_red "$(ls -alh /tmp/.a /var/tmp/.a /run/shm/a /dev/.a /dev/shm/.a 2>/dev/null)"
  print_newline
  print_blue "『WorkMiner 挖矿木马检测』"
  print_red "$(ps aux | egrep "work32|work64|/tmp/secure.sh|/tmp/auth.sh" | grep -v 'grep')"
  print_red "$(ls -alh /tmp/xmr /tmp/config.json /tmp/secure.sh /tmp/auth.sh /usr/.work/work64 2>/dev/null)"
  print_newline
}

upload_report() {
  # 发送的文件路径
#  upload_file="path_to_file"
  upload_file="$filename"
  webhook="$url/upload_media?key=$key&type=file"
  upload="curl -sk -X POST     -F 'media=@$upload_file;type=application/octet-stream' '$webhook'"
  # echo "upload => $upload"
  # upload file and extract media_id
  media_id=$(eval "$upload |jq -r .media_id")
  echo
  # send to wecomm
  filemsg='{"msgtype":"file","file":{"media_id":"'$media_id'"}}'
  curl -s -H $header -d "$filemsg" "$url/send?key=$key"
  echo
}


# 文本消息类型 [mentioned_list为@群成员id，为空则不@]
send_msg(){
  # 获取 IP 地址、hostname 和 timestamp, 可自定义消息内容, json 格式
  IP_ADDR=$(hostname -I | awk '{print $1}')
  HOSTNAME=$(hostname)
  TIMESTAMP=$(date "+%Y-%m-%d_%H:%M:%S")
  # 构建 Markdown 消息内容
  TITLE="Server Emergency Security Check Report "
  MARKDOWN_MSG=$'### '${TITLE}$'\n**IP Addr**: '${IP_ADDR}$'\n**Hostname**: '${HOSTNAME}$'\n**Timestamp**: '${TIMESTAMP}
  # 构建 JSON 数据
  JSON_DATA=$(jq -n --arg markdown_msg "$MARKDOWN_MSG" '{
      "msgtype": "markdown",
      "markdown": {
          "content": $markdown_msg
      }
  }')
  curl -s -H $header -d "$JSON_DATA" "$url/send?key=$key"
  echo
}

linux_sec_check() {
  # 基本信息采集
  basic_info_collect
  # 进程检查
  process_check
  # 网络检查
  network_check
  # 定时任务检查
  crontab_check
  # ssh 排查
  ssh_check
  # 用户文件排查
  user_check
  # 服务排查
  service_check
  # bash 排查
  bash_check
  # 黑客/后门文件排查
  file_check
  # 运行环境检查
  env_check
  # rootkit 排查
  rootkit_check
  if [ "$depth" = "true" ]; then
    # webshell 排查
    webshell_check
    # 供应链投毒排查
    poison_check
    # 挖矿排查
    miner_check
    # 上传检查文件
  fi
  # 发送企微通知消息
#  send_msg
  # 发送报告
#  upload_report
}

function helper() {
  printf "usage:  \n"
  printf "\t -v --version\t\t show script version.\n "
#  printf "\t -c --chkrootkit\t run chkrootkit.\n"
  printf "\t -a --auto\t\t run linux_sec_check.\n"
  printf "\t -d --depth\t\t run linux_sec_check in deep mode.\n"
  printf "\t -h --help\t\t print helper.\n"
}

function main() {
  # 打印脚本信息
  print_script_info
  # 基本运行环境检查
  basic_run_check
  op="${1}"
  case ${op} in
  -h | --help)
    helper
    ;;
#  -c | --chkrootkit)
#    rootkit_check
#    ;;
  -v | --version)
    echo "$VER"
    ;;
  -d | --depth)
    depth="true"
    linux_sec_check
    ;;
  -a | --auto)
    linux_sec_check
    ;;
  *)
    helper
    ;;
  esac
}

main "$@"
print_newline
print_green "Data saved to $filename"
print_dot_line
print_newline
# to clean
#sleep 3
#rm *.log
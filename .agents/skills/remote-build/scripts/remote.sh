#!/usr/bin/env bash
# Shared remote build/test box on EC2. Usage: remote.sh up <instance-type> | run <cmd...> | status | down
set -euo pipefail

DIR="${XDG_CACHE_HOME:-$HOME/.cache}/remote-build"
STATE="$DIR/state" # "<instance-id> <public-ip>", shared by all worktrees and subagents
KEY="${REMOTE_BUILD_KEY:-$HOME/.ssh/id_ed25519}"
mkdir -p "$DIR"

SSH_OPTS=(-i "$KEY" -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$DIR/known_hosts" -o LogLevel=ERROR)
host() { awk '{print $2}' "$STATE"; }
rssh() { ssh "${SSH_OPTS[@]}" "admin@$(host)" "$@"; }

need_state() { [ -f "$STATE" ] || { echo "no remote box: run 'remote.sh up <instance-type>'" >&2; exit 1; }; }

cmd_up() {
  local type=${1:?usage: remote.sh up <instance-type>}
  [ ! -f "$STATE" ] || { echo "already up: $(cat "$STATE")"; return; }

  local arch ami vpc sg ip id
  arch=$(aws ec2 describe-instance-types --instance-types "$type" \
    --query 'InstanceTypes[0].ProcessorInfo.SupportedArchitectures[0]' --output text)
  [ "$arch" = x86_64 ] && arch=amd64 || arch=arm64
  ami=$(aws ssm get-parameter --name "/aws/service/debian/release/12/latest/$arch" \
    --query Parameter.Value --output text)

  aws ec2 import-key-pair --key-name remote-build \
    --public-key-material "fileb://$KEY.pub" >/dev/null 2>&1 || true # already imported

  vpc=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)
  sg=$(aws ec2 describe-security-groups --filters Name=group-name,Values=remote-build "Name=vpc-id,Values=$vpc" \
    --query 'SecurityGroups[0].GroupId' --output text)
  if [ "$sg" = None ]; then
    sg=$(aws ec2 create-security-group --group-name remote-build --description remote-build \
      --vpc-id "$vpc" --query GroupId --output text)
  fi
  ip=$(curl -fsS https://checkip.amazonaws.com)
  aws ec2 authorize-security-group-ingress --group-id "$sg" --protocol tcp --port 22 \
    --cidr "$ip/32" >/dev/null 2>&1 || true # rule already present

  # Auto-terminates after 8h so a forgotten box cannot bill indefinitely.
  local userdata
  userdata=$(cat <<'EOF'
#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y build-essential pkg-config libssl-dev clang mold rsync curl git
su admin -c 'curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
. ~/.cargo/env
curl -L --proto =https --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash
cargo binstall -y sccache cargo-nextest'
# sccache hashes inherited CARGO_* env vars; CARGO_TARGET_DIR differs per worktree and would defeat the shared cache
printf '#!/bin/sh\nunset CARGO_TARGET_DIR\nexec sccache "$@"\n' >/home/admin/sccache-wrap
chmod +x /home/admin/sccache-wrap
touch /var/lib/remote-build-ready
shutdown -P +480
EOF
)
  id=$(aws ec2 run-instances --image-id "$ami" --instance-type "$type" --key-name remote-build \
    --security-group-ids "$sg" --user-data "$userdata" \
    --instance-initiated-shutdown-behavior terminate \
    --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=100,VolumeType=gp3}' \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=remote-build}]' \
    --query 'Instances[0].InstanceId' --output text)
  aws ec2 wait instance-running --instance-ids "$id"
  ip=$(aws ec2 describe-instances --instance-ids "$id" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
  echo "$id $ip" >"$STATE"

  for _ in $(seq 90); do # ~15 min for first-boot toolchain install
    rssh test -f /var/lib/remote-build-ready 2>/dev/null && { echo "ready: $(cat "$STATE")"; return; }
    sleep 10
  done
  echo "box never became ready; inspect with: ssh admin@$ip, then 'remote.sh down'" >&2
  exit 1
}

cmd_run() {
  need_state
  local root name
  root=$(git rev-parse --show-toplevel)
  name=$(basename "$root") # one remote dir + target dir per worktree
  cd "$root"
  # shortcut: .git is not synced (build scripts needing git history will fail), add it if one does
  rsync -az --delete --exclude /target --exclude .git \
    -e "ssh ${SSH_OPTS[*]}" --rsync-path="mkdir -p wt/$name && rsync" \
    ./ "admin@$(host):wt/$name/"
  # tests write scratch files to <root>/target, which rsync excludes
  rssh "cd wt/$name && mkdir -p target && . ~/.cargo/env && export CARGO_TARGET_DIR=\$HOME/target/$name \
    CARGO_INCREMENTAL=0 RUSTC_WRAPPER=\$HOME/sccache-wrap CARGO_BUILD_JOBS=\$((\$(nproc)/2)) \
    RUSTFLAGS='-C linker=clang -C link-arg=-fuse-ld=mold' && $(printf '%q ' "$@")"
}

cmd_status() {
  need_state
  aws ec2 describe-instances --instance-ids "$(awk '{print $1}' "$STATE")" \
    --query 'Reservations[0].Instances[0].[InstanceId,InstanceType,State.Name,PublicIpAddress]' --output text
}

cmd_down() {
  need_state
  aws ec2 terminate-instances --instance-ids "$(awk '{print $1}' "$STATE")" >/dev/null
  rm -f "$STATE"
  echo "terminated"
}

case "${1:-}" in
  up) shift; cmd_up "$@" ;;
  run) shift; cmd_run "$@" ;;
  status) cmd_status ;;
  down) cmd_down ;;
  *) sed -n '2p' "$0" >&2; exit 2 ;;
esac

#!/bin/bash

# Define the log paths
fail2ban_log="/var/log/fail2ban.log"
ufw_log="/var/log/ufw.log"

# Define the destination directory using the current user's home directory
destination_dir="$HOME"

# Copy the logs to the destination directory
sudo cp $fail2ban_log $destination_dir/
sudo cp $ufw_log $destination_dir/

# Change the ownership to the current user
sudo chown $USER:$USER $destination_dir/fail2ban.log
sudo chown $USER:$USER $destination_dir/ufw.log

# Change permissions to make the log files readable
sudo chmod 644 $destination_dir/fail2ban.log
sudo chmod 644 $destination_dir/ufw.log

echo "Logs have been copied to $destination_dir and permissions updated for user $USER."

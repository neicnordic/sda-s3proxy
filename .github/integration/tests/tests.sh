#!/bin/bash

# Function checking that a file was uploaded to the S3 backend
function check_output_status() {
    if [[ $1 -eq 0 ]]; then
        echo -e "\u2705 Test passed, expected response found"
    else
        echo -e "\u274c Test failed, expected response not found"
        exit 1
    fi
}

cd dev_utils || exit 1

s3cmd -c directS3 put README.md s3://test/some_user/ || exit 1

echo "- Testing allowed actions"

# Put file into bucket
echo "Trying to upload a file to user's bucket"
output=$(s3cmd -c proxyS3 put README.md s3://dummy/ >/dev/null 2>&1)
check_output_status "$output"

# List objects
echo "Trying to list user's bucket"
output=$(s3cmd -c proxyS3 ls s3://dummy 2>&1 | grep -q "README.md")
check_output_status "$output"

# ---------- Test forbidden actions ----------
forbidden="Forbidden"
unauthorized="Unauthorized"
nobucket="NoSuchBucket"
notfound="Not Found"

echo "- Testing forbidden actions"

# Make bucket
echo "Trying to create bucket"
output=$(s3cmd -c proxyS3 mb s3://test_bucket 2>&1 | grep -q $forbidden)
check_output_status "$output"

# Remove bucket
echo "Trying to remove bucket"
output=$(s3cmd -c proxyS3 rb s3://test 2>&1 | grep -q $forbidden)
check_output_status "$output"

# List buckets
echo "Trying to list all buckets"
output=$(s3cmd -c proxyS3 ls s3:// 2>&1 | grep -q $forbidden)
check_output_status "$output"

# List all objects in all buckets
echo "Trying to list all objects in all buckets"
output=$(s3cmd -c proxyS3 la s3:// 2>&1 | grep -q $forbidden)
check_output_status "$output"

# Put file into another user's bucket
echo "Trying to upload a file to another user's bucket"
output=$(s3cmd -c proxyS3 put README.md s3://some_user/ 2>&1 | grep -q $unauthorized)
check_output_status "$output"

# Get file from another user's bucket
echo "Trying to get a file from another user's bucket"
output=$(s3cmd -c proxyS3 get s3://some_user/README.md local_file.md 2>&1 | grep -q $unauthorized)
check_output_status "$output"

# Get file from own bucket
echo "Trying to get a file from user's bucket"
output=$(s3cmd -c proxyS3 get s3://dummy/README.md local_file.md 2>&1 | grep -q $nobucket)
check_output_status "$output"

# Delete file from bucket
echo "Trying to delete a file from user's bucket"
output=$(s3cmd -c proxyS3 del s3://dummy/README.md 2>&1 | grep -q $forbidden)
check_output_status "$output"

# Disk usage by buckets
echo "Trying to get disk usage for user's bucket"
output=$(s3cmd -c proxyS3 du s3://dummy 2>&1 | grep -q $forbidden)
check_output_status "$output"

# Get various information about user's bucket
echo "Trying to get information about for user's bucket"
output=$(s3cmd -c proxyS3 info s3://dummy 2>&1 | grep -q $forbidden)
check_output_status "$output"

# Get various information about user's file
echo "Trying to get information about user's file"
output=$(s3cmd -c proxyS3 info s3://dummy/README.md 2>&1 | grep -q "$notfound")
check_output_status "$output"

# Move object
echo "Trying to move file to another location"
output=$(s3cmd -c proxyS3 mv s3://dummy/README.md s3://dummy/test 2>&1 | grep -q $forbidden)
check_output_status "$output"

# Copy object
echo "Trying to copy file to another location"
output=$(s3cmd -c proxyS3 cp s3://dummy/README.md s3://dummy/test 2>&1 | grep -q $forbidden)
check_output_status "$output"

# Modify access control list for file
echo "Trying to modify acl for user's file"
output=$(s3cmd -c proxyS3 setacl s3://dummy/README.md --acl-public 2>&1 | grep -q $forbidden)
check_output_status "$output"

# Show multipart uploads - when multipart enabled, add all relevant tests
echo "Trying to list multipart uploads"
output=$(s3cmd -c proxyS3 multipart s3://dummy/ 2>&1 | grep -q $nobucket)
check_output_status "$output"

# Enable/disable bucket access logging
echo "Trying to change the access logging for a bucket"
output=$(s3cmd -c proxyS3 accesslog s3://dummy/ 2>&1 | grep -q $nobucket)
check_output_status "$output"

echo "All tests have passed"

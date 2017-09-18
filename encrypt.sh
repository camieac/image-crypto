# Name: ppm-encrypt.sh
# Desc.: Encrypt a PPM image using ECB and CBC AES modes
#        Thanks to:
#           - https://blog.filippo.io/the-ecb-penguin/
#           - https://en.wikipedia.org/wiki/User:Lunkwill
# Author: Cameron A. Craig
# Date: 17/09/2017

# Make sure an argument is given, otherwise print help
if [ $# -eq 0 ]
then
  echo "No image given!"
  exit
fi

# Get image name from first argument


if [ -f $1 ]
then
  IMAGE_PATH=$1
else
  echo "Could not find given image: $1"
  exit
fi

echo "Encrypting image $IMAGE_PATH"

# TODO: Find length of header
# For now se assume header length is 3 lines
# perl -ne 'print "$. $_" if m/[\x80-\xFF]/'
HEADER_LINES=3

# Keep the header for the final image
head -n $HEADER_LINES $IMAGE_PATH > header.txt

# Seperate the binary data into its own file
tail -n +$(($HEADER_LINES+1)) $IMAGE_PATH > image.bin

# Encrypt with ECB
openssl enc -aes-128-ecb -nosalt -pass pass:"PASS" -in image.bin -out image.ecb.bin
# Join original header and the encrypted image, into a new file
cat header.txt image.ecb.bin > $IMAGE_PATH.ecb.ppm

# Encrypt with CBC
openssl enc -aes-128-cbc -nosalt -pass pass:"PASS" -in image.bin -out image.cbc.bin
# Join original header and the encrypted image, into a new file
cat header.txt image.cbc.bin > $IMAGE_PATH.cbc.ppm


# Remove temporary files
rm header.txt
rm image.bin
rm image.cbc.bin
rm image.ecb.bin


echo "Encrypted image saved to $IMAGE_PATH.ecb.ppm"

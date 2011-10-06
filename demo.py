from paperTrust import PaperTrust
import Image, ImageDraw, ImageFont
import datetime
import os

if __name__ == "__main__":
  pt = PaperTrust()
  priv_filename = 'demo-private.pem'
  pub_filename = 'demo-public.pem'
  org_uuid = '12c1ba14-bfaf-5a3c-af40-50845338b6c7'
  
  print "Generating Demo Check"
  pt.set_signing_organization(org_uuid)
  
  from_file = pt.load_sign_org_private_rsa_key_from_file(priv_filename)
  #print "Load private key from file: %s" % from_file
  with open(priv_filename) as priv_file:
    from_string = pt.load_sign_org_private_rsa_key_from_string(priv_file.read())
    #print "Load private key from string: %s" % from_string
  
  check_data = {'account': '123-456-7', 'routing':'123456780', 'recipient':'Kyle Dickerson', 'amount':'$1234.56'}
  sig_img = pt.create_signature(check_data)
  
  # Create a check:
  blank_check = Image.open('blankcheck.jpg').convert('L')
  blank_check.paste(sig_img.resize((int(sig_img.size[0]*1.5), int(sig_img.size[1]*1.5))), (1005,403))
  draw = ImageDraw.Draw(blank_check)
  font = ImageFont.load("helvR24.pil")
  draw.text((240, 255), check_data['recipient'], font=font)
  draw.text((1184, 260), check_data['amount'], font=font)
  draw.text((988, 140), str(datetime.date.today()), font=font) 
  draw.text((64, 340), 'One thousand two hundred thirty four and 56/100', font=font)
  blank_check.save('filled_check.png')

  print "Check Created and saved"
  print_check = raw_input("Print check? (y|n): ")
  if print_check == 'y': os.system('lpr -o ppi=200 filled_check.png')
  
  with open(pub_filename) as pub_file:
    pub_str = pub_file.read()
    pt.set_verify_org_lookup_callback(lambda org_id: (org_id, 'PaperTrust Demo Organization', pub_str))
    #from_string = pt.load_public_rsa_key_from_string(pub_str)
    #print "Load public key from string: %s" % from_string
  
  scan_video = raw_input("Scan Video? (y|n): ")
  if scan_video == 'y':
    print "Checking for QRCodes in Video"
    found_sigs = pt.verify_signatures_from_video()
    for verified, data, org_name, sig in found_sigs:
      print "----------------------------"
      for key, value in data.iteritems():
        print "%s -> %s" % (key, value)
      print "Sig (base 64): %s" % sig
      if verified:
        print "Signature Successfully Verified: Signed by '%s'" % (org_name)
      else:
        print "Signature is Invalid!"
      print "----------------------------"

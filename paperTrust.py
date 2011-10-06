# PaperTrust
import M2Crypto
import os
import Image
import zbar
import qrencode
import datetime
import time

# PaperTrustManager
import uuid
import urllib2

class PaperTrustManager:
  UUID_NAMESPACE = 'paperTrust.com'
  PUBKEY_URL = 'https://paperTrust.com/get_pubkey?org_uuid=%s'
  
  def generate_uuid(self):
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, UUID_NAMESPACE))
    
  def lookup_org_by_id(self, org_uuid):
    resp = urllib2.urlopen(PUBKEY_URL % org_uuid) # Doesn't do https authentication, should do that ourselves
    org_name = 'PaperTrust'
    org_pub_key = ''
    return resp.read()
  
class RSAKeyMaker:
  def __init__(self):
    self._rsa_key = None
  
  def create_keys(self, num_bits=1024):
    M2Crypto.Rand.rand_seed(os.urandom(num_bits))
    self._rsa_key = M2Crypto.RSA.gen_key(num_bits, RSA_PUBLIC_EXPONENT)

  def save_keys(self, name_prefix=u"PaperTrust_generated", file_location="./", private_key_password=None):
    self.save_private_key(u"%s-private-key.pem" % name_prefix, file_location, private_key_password)
    self.save_public_key(u"%s-public-key.pem" % name_prefix, file_location)

  def save_private_key(self, name=u"PaperTrust_generated-private-key.pem", file_location="./", private_key_password=None):
    params = {}
    if not private_key_password: params['cipher'] = None
    else: params['callback'] = lambda: private_key_password
    self._rsa_key.save_key(os.path.join(file_location, name), **params)
  
  def save_public_key(self, name=u"PaperTrust_generated-public-key.pem", file_location="./"):
    self._rsa_key.save_pub_key(os.path.join(file_location, name))

class PaperTrust:
  RSA_PUBLIC_EXPONENT = 65537
  ENTRY_DELIMITER = unichr(2029) # 2029 = Paragraph Separator
  KEY_VALUE_DELIMITER = unichr(2028) # 2028 = Line Separator
  PREAMBLE = u'PaperTrust'

  def __init__(self):
	# sign->private_key and verify->public_key are both RSA keys
    self._sign_org = {'uuid':None, 'name':None, 'private_key':None}
    self._verify_org = {'uuid':None, 'name':None, 'public_key':None, 'lookup':None} # lookup: callable with uuid as param

  # The organization ID assigned by PaperTrust
  # This ID will be stored with the other signed data
  # Clients will use this ID to lookup public keys via the PaperTrust online API
  # an org_id is a UUID version 5 (truncated SHA-1 hash), provided to you by PaperTrust when your account is verified
  def set_signing_organization(self, org_uuid, org_private_key=None):
    self._sign_org['uuid'] = org_uuid
    if org_private_key: self.load_sign_org_private_rsa_key_from_string(org_private_key)
  
  def set_verifying_organization(self, org_uuid, org_name, org_public_key=None):
	self._verify_org['uuid'] = org_uuid
	self._verify_org['name'] = org_name
	if org_public_key: self.load_verify_org_public_rsa_key_from_string(org_public_key)
  
  def load_sign_org_private_rsa_key_from_file(self, rsa_key_filename, rsa_key_password=None):
    self._sign_org['private_key'] = None
    self._sign_org['private_key'] = M2Crypto.RSA.load_key(rsa_key_filename, lambda: rsa_key_password)
    return (self._sign_org['private_key'] is not None)
  
  def load_sign_org_private_rsa_key_from_string(self, rsa_key_string, rsa_key_password=None):
    self._sign_org['private_key'] = None
    self._sign_org['private_key'] = M2Crypto.RSA.load_key_string(rsa_key_string, lambda: rsa_key_password)
    return (self._sign_org['private_key'] is not None)
  
  def load_verify_org_public_rsa_key_from_file(self, rsa_key_filename):
    self._verify_org['public_key'] = None
    self._verify_org['public_key'] = M2Crypto.RSA.load_pub_key(rsa_key_filename)
    return (self._verify_org['public_key'] is not None)
  
  def load_verify_org_public_rsa_key_from_string(self, rsa_key_string):
    self._verify_org['public_key'] = None
    # For unknown reasons, you can't directly load a public key from a string, so we have to wrap it in a Bio.MemoryBuffer
    bio_mem_buf = M2Crypto.BIO.MemoryBuffer(rsa_key_string)
    self._verify_org['public_key'] = M2Crypto.RSA.load_pub_key_bio(bio_mem_buf)
    return (self._verify_org['public_key'] is not None)
  
  # We need to get public keys based on the Organization ID contained in the QR Code
  # Register a function here which will be used to find the public key of an Organization by Org_ID
  # The function must take an Org_ID as input and return the public_key as a string in PEM format
  # The function will only be called if a public key is not set otherwise
  def set_verify_org_lookup_callback(self, callback):
    self._verify_org['lookup'] = callback
  
  # provide data as map-like object (has keys, can index by keys)
  def __data_to_string(self, data):
    data_entries = []
    for key in sorted(data.keys()):
      data_entries.append(u'%s%s%s' % (unicode(key), self.KEY_VALUE_DELIMITER, unicode(data[key])))
    return self.ENTRY_DELIMITER.join(data_entries)
  
  # Creates a base64-encoded signature for the provided string
  def __sign_string(self, string):
    evp_key = M2Crypto.EVP.PKey()
    evp_key.assign_rsa(self._sign_org['private_key'])
    evp_key.sign_init()
    evp_key.sign_update(string)
    sig_string = evp_key.sign_final()
    sig_string = sig_string.encode('base64')
    return sig_string
  
  # takes map-like data object (has keys() can index values with data[key])
  # returns QRCode as PIL.Image
  def create_signature(self, data):
    if (self._sign_org['private_key'] is None):
      raise Exception('No private key available for signing.  Load private key first.')
    if (self._sign_org['uuid'] is None):
      raise Exception('No Organization UUID available.  Set the Organization UUID first')
    timestamp = datetime.datetime.now().replace(microsecond = 0)
    timestamp_str = unicode(timestamp) + (u' UTC%s' % u'-' if time.timezone > 0 else u'+') + unicode(abs(time.timezone / 60 / 60))
    data_copy = data.copy()
    data_copy[u"pt_timestamp"] = timestamp_str
    data_copy[u"org_uuid"] = self._sign_org['uuid']
    data_list_str = self.__data_to_string(data_copy)
    data_sig = self.__sign_string(data_list_str)
    #data_list_str += u'!' # test altering the data after signature is created
    data_str = self.PREAMBLE + self.ENTRY_DELIMITER
    data_str += data_list_str
    data_str += u'%s%s' % (self.ENTRY_DELIMITER, unicode(data_sig))
    qr_code = qrencode.encode_scaled(data_str.encode('utf-8').encode('base64'), 200)
    return qr_code[2]
  
  def __handle_decoded_image(self, decoded_image):
    discovered_codes = []
    for symbol in decoded_image:
      if str(symbol.type) == 'QRCODE' and symbol.count == 0: # 0 -> good symbol, <0 -> uncertain, >0 -> duplicate
        code = symbol.data.decode('base64').decode('utf-8')
        preamble, data_str = code.split(self.ENTRY_DELIMITER, 1)
        if preamble != self.PREAMBLE:
          continue
        data_str, sig = data_str.rsplit(self.ENTRY_DELIMITER, 1)
        data_map = {}
        for data_entry in data_str.split(self.ENTRY_DELIMITER):
          key, val = data_entry.split(self.KEY_VALUE_DELIMITER)
          data_map[key] = val
        
        evp_key = M2Crypto.EVP.PKey()
        if not self._verify_org['public_key']:
          #print "Attempting public key lookup via callback"
          self.set_verifying_organization(*(self._verify_org['lookup'](data_map[u"org_uuid"])))
        if not self._verify_org['public_key']:
          raise Exception('No public key provided and none found during lookup via callback.')
        
        evp_key.assign_rsa(self._verify_org['public_key'])
        evp_key.verify_init()
        evp_key.verify_update(data_str)
        verified = evp_key.verify_final(sig.decode('base64'))
        discovered_codes.append((verified==1, data_map, self._verify_org['name'], sig))
    return discovered_codes
  
  def verify_signatures_from_video(self, video_device='/dev/video0'):
    if (self._verify_org['public_key'] is None and self._verify_org['lookup'] is None):
      raise Exception('No public key available for verifying.  Load public key first OR provide lookup callback function.')
    
    proc = zbar.Processor()
    proc.parse_config('enable')
    proc.init(video_device)
    discovered_codes = []

    def data_handler(proc, image, closure):
      print "Got ONE!"
      discovered_codes.extend(self.__handle_decoded_image(image))
      
    proc.set_data_handler(data_handler)
    proc.visible = True
    proc.process_one()
    proc.visible = False
    
    return discovered_codes
  
  # takes PIL.Image
  # return list of tuples: [(verified_boolean, data_map, org_name, base64-encoded-signature)] for all QRCodes found in image
  def verify_signatures_from_image(self, image):
    if (self._verify_org['public_key'] is None and self._verify_org['lookup'] is None):
      raise Exception('No public key available for verifying.  Load public key first OR provide lookup callback function.')
    image_copy = image.copy().convert('L')
    scanner = zbar.ImageScanner()
    scanner.parse_config('enable')
    width, height = image_copy.size
    raw = image_copy.tostring()
    zbar_image = zbar.Image(width, height, 'Y800', raw)
    discovered_codes = self.__handle_decoded_image(zbar_image)
    return discovered_codes

if __name__ == "__main__":
  pt = PaperTrust()
  priv_filename = 'demo-private.pem'
  pub_filename = 'demo-public.pem'
  org_uuid = '12c1ba14-bfaf-5a3c-af40-50845338b6c7'
  
  pt.set_signing_organization(org_uuid)
  
  from_file = pt.load_sign_org_private_rsa_key_from_file(priv_filename)
  print "Load private key from file: %s" % from_file
  with open(priv_filename) as priv_file:
    from_string = pt.load_sign_org_private_rsa_key_from_string(priv_file.read())
    print "Load private key from string: %s" % from_string
  
  check_data = {'account': '1234567', 'routing':'5463728', 'recipient':'Kyle Dickerson', 'amount':'1234.56'}
  sig_img = pt.create_signature(check_data)
  #sig_img.save('testing_4_21.png')
  
  print "Created Signature QRCode"
  #from_file = pt.load_public_rsa_key_from_file(pub_filename)
  #print "Load public key from file: %s" % from_file
  with open(pub_filename) as pub_file:
    pub_str = pub_file.read()
    pt.set_verify_org_lookup_callback(lambda org_id: (org_id, 'PaperTrust Demo Organization', pub_str))
    #from_string = pt.load_public_rsa_key_from_string(pub_str)
    #print "Load public key from string: %s" % from_string
  
  found_sigs = pt.verify_signatures_from_image(sig_img)
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

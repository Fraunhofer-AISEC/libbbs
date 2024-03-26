require 'json'

$gen_header = false
if ARGV.length.positive? and ARGV[0] == "header"
  $gen_header = true
end

# File inputs
# To regenerate the fixtures.h, let this point to your fixture_data dir
base_dir = 'fixture_data/'
messages = JSON.parse File.read(base_dir + 'messages.json')
shake_keypair = JSON.parse File.read(base_dir + 'bls12-381-shake-256/keypair.json')
shake_scalars = JSON.parse File.read(base_dir + 'bls12-381-shake-256/MapMessageToScalarAsHash.json')
shake_generators = JSON.parse File.read(base_dir + 'bls12-381-shake-256/generators.json')
shake_signatures = (1..10).map do |n|
  file_name = "#{base_dir}bls12-381-shake-256/signature/signature#{n.to_s.rjust(3,'0')}.json"
  JSON.parse File.read(file_name)
end
shake_mockedRng = JSON.parse File.read(base_dir + 'bls12-381-shake-256/mockedRng.json')
shake_h2s = JSON.parse File.read(base_dir + 'bls12-381-shake-256/h2s.json')
shake_proofs = (1..15).map do |n|
  file_name = "#{base_dir}bls12-381-shake-256/proof/proof#{n.to_s.rjust(3,'0')}.json"
  JSON.parse File.read(file_name)
end
sha_keypair = JSON.parse File.read(base_dir + 'bls12-381-sha-256/keypair.json')
sha_scalars = JSON.parse File.read(base_dir + 'bls12-381-sha-256/MapMessageToScalarAsHash.json')
sha_generators = JSON.parse File.read(base_dir + 'bls12-381-sha-256/generators.json')
sha_signatures = (1..10).map do |n|
  file_name = "#{base_dir}bls12-381-sha-256/signature/signature#{n.to_s.rjust(3,'0')}.json"
  JSON.parse File.read(file_name)
end
sha_mockedRng = JSON.parse File.read(base_dir + 'bls12-381-sha-256/mockedRng.json')
sha_h2s = JSON.parse File.read(base_dir + 'bls12-381-sha-256/h2s.json')
sha_proofs = (1..15).map do |n|
  file_name = "#{base_dir}bls12-381-sha-256/proof/proof#{n.to_s.rjust(3,'0')}.json"
  JSON.parse File.read(file_name)
end
shake_expand_message = JSON.parse File.read(base_dir + 'bls12-381-shake-256/expandMessage.json')

def comment(s)
  puts "// #{s}"
end

# Smaller files through aliases
$hex_to_name = {}

def hex_string(name, s)
  prefix = "fixture_"
  short = false
  if $hex_to_name[s]
    #puts "unsigned char #{prefix}#{name}[] = #{prefix}#{$hex_to_name[s]};"
    puts "#define #{prefix}#{name} #{prefix}#{$hex_to_name[s]}" if $gen_header
  else
    arr = s.scan(/.{1,2}/).map{|x| "0x#{x}"}
    $hex_to_name[s] = name
    preamble = "uint8_t  #{prefix}#{name}[] ="
    short = (preamble.length + arr.length*5 + 3 <= 100)
    if $gen_header
      puts "extern uint8_t  #{prefix}#{name}[#{arr.length}];"
    elsif short
      puts "#{preamble} {#{arr.join(',')}};"
    else
      puts preamble
      idx = 0
      while idx < arr.length
        start_char = ' '
        start_char = '{' if idx == 0
        end_char = ','
        end_char = '};' if idx + 16 >= arr.length
        puts "\t\t#{start_char}#{arr[idx, 16].join(',')}#{end_char}"
        idx += 16
      end
    end
  end
end

def ascii_string_to_c_array(name, ascii_string)
  if $gen_header
    puts "extern uint8_t #{name}[];"
    return
  end
  # Prefix for the variable name to clearly identify it's an array
  prefix = "uint8_t "
  # Convert each character in the string to its ASCII value
  ascii_values = ascii_string.bytes.map { |byte| byte.to_s }
  # Join the ASCII values with commas and space for C array initialization
  array_content = ascii_values.join(', ')
  # Construct the C declaration for the array
  c_declaration = "#{prefix}#{name}[] = { #{array_content} };"
  puts c_declaration
end

def print_size_t_variable(variable_name, hex_string)
  if $gen_header
    puts "extern size_t #{variable_name};"
    return
  end
  # Convert the hex string to an integer to ensure it's a valid number
  normalized_hex = hex_string.delete_prefix('0x')
  number = normalized_hex.to_i(16)
  # Prepare the C code for declaring and initializing a size_t variable
  # Note: "%#x" formats the number back into hex, ensuring it includes the '0x' prefix
  c_declaration = "size_t #{variable_name} = %#x;" % number
  puts c_declaration
end

def number_array(name, a)
  prefix = "fixture_"
  if $gen_header
    puts "extern uint64_t #{prefix}#{name}[#{a.length}];"
  else
    puts "uint64_t #{prefix}#{name}[] = {#{a.join(', ')}};"
  end
end

def print_signature(sig, prefix)
  sig['messages'].each_with_index do |m,idx|
    hex_string(prefix + "m_#{idx+1}", m)
  end
  hex_string(prefix + "SK", sig['signerKeyPair']['secretKey'])
  hex_string(prefix + "PK", sig['signerKeyPair']['publicKey'])
  hex_string(prefix + "header", sig['header'])
  hex_string(prefix + "B", sig['trace']['B'])
  hex_string(prefix + "domain", sig['trace']['domain'])
  hex_string(prefix + "signature", sig['signature'])
end

def print_proof(proof, prefix)
  proof['messages'].each_with_index do |m,idx|
    hex_string(prefix + "m_#{idx+1}", m)
  end
  hex_string(prefix + "public_key", proof['signerPublicKey'])
  hex_string(prefix + "signature", proof['signature'])
  hex_string(prefix + "header", proof['header'])
  hex_string(prefix + "presentation_header", proof['presentationHeader'])
  number_array(prefix + "revealed_indexes", proof['disclosedIndexes'])
  hex_string(prefix + "r1", proof['trace']['random_scalars']['r1'])
  hex_string(prefix + "r2", proof['trace']['random_scalars']['r2'])
  hex_string(prefix + "e_tilde", proof['trace']['random_scalars']['e_tilde'])
  hex_string(prefix + "r1_tilde", proof['trace']['random_scalars']['r1_tilde'])
  hex_string(prefix + "r3_tilde", proof['trace']['random_scalars']['r3_tilde'])
  mt_idx = -1
  proof['trace']['random_scalars']['m_tilde_scalars'].each do |s|
    mt_idx = ((0..proof['messages'].length).reject do |x|
      x <= mt_idx || proof['disclosedIndexes'].include?(x)
    end)[0]
    hex_string(prefix + "m_tilde_#{mt_idx}", s)
  end
  hex_string(prefix + "T1", proof['trace']['T1'])
  hex_string(prefix + "T2", proof['trace']['T2'])
  hex_string(prefix + "domain", proof['trace']['domain'])
  hex_string(prefix + "proof", proof['proof'])
end

comment("This file is generated from genfixtures.rb")
comment("DO NOT EDIT THIS FILE DIRECTLY!")
puts
if $gen_header
  puts '#ifndef FIXTURESH'
  puts '#define FIXTURESH'
  puts
  puts '#include <stdint.h>'
  puts '#include <stddef.h>'
else
  puts '#include "fixtures.h"'
end
puts

comment("Messages")
messages.each_with_index do |m,idx|
  hex_string("m_#{idx+1}", m)
end

puts
comment("")
comment("BLS12-381-SHAKE-256 Test Vectors")
comment("")
shake = "bls12_381_shake_256_"

puts
comment("Key Pair")
hex_string(shake + "key_material", shake_keypair['keyMaterial'])
hex_string(shake + "key_info", shake_keypair['keyInfo'])
hex_string(shake + "key_dst", shake_keypair['keyDst'])
hex_string(shake + "SK", shake_keypair['keyPair']['secretKey'])
hex_string(shake + "PK", shake_keypair['keyPair']['publicKey'])

puts
comment("Map Messages to Scalars")
shake_scalars['cases'].each_with_index do |m,idx|
  hex_string(shake + "msg_scalar_#{idx+1}", m['scalar'])
end

puts
comment("Message Generators")
hex_string(shake + "Q_1", shake_generators['Q1'])
shake_generators['MsgGenerators'].each_with_index do |m,idx|
  hex_string(shake + "H_#{idx+1}", m)
end

puts
comment("Signature Fixtures")
puts
comment("Valid Single Message Signature")
print_signature(shake_signatures[0], shake + "signature1_")

puts
comment("Valid Multi-Message Signature")
# Yes, the indices are out of order. I choose the ID-order over the fixtures order
print_signature(shake_signatures[3], shake + "signature2_")

puts
comment("Proof Fixtures")
puts
comment("Mocked random scalar generation (all hex)")
hex_string(shake + "proof_SEED", shake_mockedRng['seed'])
hex_string(shake + "proof_DST", shake_mockedRng['dst'])
shake_mockedRng['mockedScalars'].each_with_index do |m,idx|
  hex_string(shake + "proof_random_scalar_#{idx+1}", m)
end

puts
comment("Valid Single Message Proof")
comment("NOTE: We denote m_0 as m_1 like in all other proofs")
print_proof(shake_proofs[0], shake + "proof1_")

puts
comment("Valid Multi-Message, All Messages Disclosed Proof")
print_proof(shake_proofs[1], shake + "proof2_")

puts
comment("Valid Multi-Message, Some Messages Disclosed Proof")
print_proof(shake_proofs[2], shake + "proof3_")

puts
comment("")
comment("BLS12-381-SHA-256 Test Vectors")
comment("")
sha = "bls12_381_sha_256_"

puts
comment("Key Pair")
hex_string(sha + "key_material", sha_keypair['keyMaterial'])
hex_string(sha + "key_info", sha_keypair['keyInfo'])
hex_string(sha + "key_dst", sha_keypair['keyDst'])
hex_string(sha + "SK", sha_keypair['keyPair']['secretKey'])
hex_string(sha + "PK", sha_keypair['keyPair']['publicKey'])

puts
comment("Map Messages to Scalars")
sha_scalars['cases'].each_with_index do |m,idx|
  hex_string(sha + "msg_scalar_#{idx+1}", m['scalar'])
end

puts
comment("Message Generators")
hex_string(sha + "Q_1", sha_generators['Q1'])
sha_generators['MsgGenerators'].each_with_index do |m,idx|
  hex_string(sha + "H_#{idx+1}", m)
end

puts
comment("Signature Fixtures")
puts
comment("Valid Single Message Signature")
print_signature(sha_signatures[0], sha + "signature1_")

puts
comment("Valid Multi-Message Signature")
# Yes, the indices are out of order. I choose the ID-order over the fixtures order
print_signature(sha_signatures[3], sha + "signature2_")

puts
comment("Proof Fixtures")
puts
comment("Mocked random scalar generation (all hex)")
hex_string(sha + "proof_SEED", sha_mockedRng['seed'])
hex_string(sha + "proof_DST", sha_mockedRng['dst'])
sha_mockedRng['mockedScalars'].each_with_index do |m,idx|
  hex_string(sha + "proof_random_scalar_#{idx+1}", m)
end

puts
comment("Valid Single Message Proof")
comment("NOTE: We denote m_0 as m_1 like in all other proofs")
print_proof(sha_proofs[0], sha + "proof1_")

puts
comment("Valid Multi-Message, All Messages Disclosed Proof")
print_proof(sha_proofs[1], sha + "proof2_")

puts
comment("Valid Multi-Message, Some Messages Disclosed Proof")
print_proof(sha_proofs[2], sha + "proof3_")

puts
comment("")
comment("Additional Test Vectors - BLS12-381-SHAKE-256 Ciphersuite")
comment("")

puts
comment("Signature Test Vectors")

puts
comment("No Header Valid Signature")
print_signature(shake_signatures[9], shake + "a_signature1_")

puts
comment("Modified Message Signature")
print_signature(shake_signatures[1], shake + "a_signature2_")

puts
comment("Extra Unsigned Message Signature")
print_signature(shake_signatures[2], shake + "a_signature3_")

puts
comment("Missing Message Signature")
print_signature(shake_signatures[4], shake + "a_signature4_")

puts
comment("Reordered Message Signature")
print_signature(shake_signatures[5], shake + "a_signature5_")

puts
comment("Wrong Public Key Signature")
print_signature(shake_signatures[6], shake + "a_signature6_")

puts
comment("Wrong Header Signature")
print_signature(shake_signatures[7], shake + "a_signature7_")

puts
comment("Proof Test Vectors")

puts
comment("No Header Valid Proof")
print_proof(shake_proofs[13], shake + "a_proof1_")

puts
comment("No Presentation Header Valid Proof")
print_proof(shake_proofs[14], shake + "a_proof2_")

puts
comment("Hash to Scalar Test Vectors")
hex_string(shake + "h2s_msg", shake_h2s['message'])
hex_string(shake + "h2s_dst", shake_h2s['dst'])
hex_string(shake + "h2s_scalar", shake_h2s['scalar'])

puts
comment("")
comment("Additional Test Vectors - BLS12-381-SHA-256 Ciphersuite")
comment("")

puts
comment("Signature Test Vectors")

puts
comment("No Header Valid Signature")
print_signature(sha_signatures[9], sha + "a_signature1_")

puts
comment("Modified Message Signature")
print_signature(sha_signatures[1], sha + "a_signature2_")

puts
comment("Extra Unsigned Message Signature")
print_signature(sha_signatures[2], sha + "a_signature3_")

puts
comment("Missing Message Signature")
print_signature(sha_signatures[4], sha + "a_signature4_")

puts
comment("Reordered Message Signature")
print_signature(sha_signatures[5], sha + "a_signature5_")

puts
comment("Wrong Public Key Signature")
print_signature(sha_signatures[6], sha + "a_signature6_")

puts
comment("Wrong Header Signature")
print_signature(sha_signatures[7], sha + "a_signature7_")

puts
comment("Proof Test Vectors")

puts
comment("No Header Valid Proof")
print_proof(sha_proofs[13], sha + "a_proof1_")

puts
comment("No Presentation Header Valid Proof")
print_proof(sha_proofs[14], sha + "a_proof2_")

puts
comment("Hash to Scalar Test Vectors")
hex_string(sha + "h2s_msg", sha_h2s['message'])
hex_string(sha + "h2s_dst", sha_h2s['dst'])
hex_string(sha + "h2s_scalar", sha_h2s['scalar'])

puts
comment("")
comment("RFC 9380 K.6 expand_message_xof SHAKE256 Test Vectors")
comment("")

expand_message_xof = "rfc_9380_k6_expand_message_xof_"

puts
comment("Expand Message Test Vectors")
ascii_string_to_c_array(expand_message_xof + "dst", shake_expand_message['DST'])
shake_expand_message['vectors'].each_with_index do |m,idx|
  ascii_string_to_c_array(expand_message_xof + "msg_#{idx+1}", m["msg"])
  print_size_t_variable(expand_message_xof + "len_#{idx+1}", m["len_in_bytes"])
  hex_string(expand_message_xof + "dst_prime#{idx+1}", m["DST_prime"])
  hex_string(expand_message_xof + "msg_prime#{idx+1}", m["msg_prime"])
  hex_string(expand_message_xof + "output#{idx+1}", m["uniform_bytes"])
end

if $gen_header
  puts
  puts '#endif /* FIXTURESH */'
end

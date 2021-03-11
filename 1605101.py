from BitVector import *
import datetime
from collections import deque
import binascii
import PyPDF2
from PIL import Image


# CONSTANTS ARE GENERATED OR HARDCODED HERE

AES_modulus = BitVector(bitstring='100011011')


Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]

InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]

def generate_s_box():

    sbox = [0x63]
    for i in range(1, 256):
        mulInvBv = BitVector(intVal=i, size=8).gf_MI(AES_modulus, 8)

        s = BitVector(intVal=0x63, size=8) ^ mulInvBv ^ (mulInvBv << 1) ^ (
            mulInvBv << 1) ^ (mulInvBv << 1) ^ (mulInvBv << 1)

        sbox.append(s.int_val())

    return sbox

def generate_inverse_s_box():

    invSBox = []
    for i in range(0, 256):
        inp = BitVector(intVal=i, size=8)

        b = BitVector(intVal=0x05, size=8) ^ (
            inp << 1) ^ (inp << 2) ^ (inp << 3)

        if(b.int_val() == 0):
            s = BitVector(hexstring="00")

        else:
            s = b.gf_MI(AES_modulus, 8)

        invSBox.append(s.int_val())

    return invSBox


 # Generating the SBox & InvSBox at the start
Sbox = generate_s_box()
InvSbox = generate_inverse_s_box()

# print( hex(InvSbox[0x63]) )

##############################################################################################################################

# UTILITY FUNCTIONS


# This will be used by both encrypt and decrypt functions
def add_round_key( stateMatrix , roundKeyMatrix ):
    resultMatrix = []
    
    for itr in range( len(stateMatrix) ):
        tempArr = []
        for itemPT , itemTK in zip( stateMatrix[itr] , roundKeyMatrix[itr] ):
            tempArr.append( itemPT ^ itemTK )
        resultMatrix.append(tempArr)

    return resultMatrix

def convert_to_matrix ( string , choice ):
    
    # String either needs to be truncated or padded to only include 16 characters
    usedString = string[:16] + ' ' * ( 16 - len(string) )
    
    # Converting to hex array
    convertedArr = [r'%x'%ord(c) for c in usedString ]
    bvArr = [ BitVector( hexstring=item ) for item in convertedArr]

    # the matrix for key will be stored here
    matrix = convert_1D_to_2D_array( 4 , bvArr )


    return ( choice == 'key' ) and matrix or transpose_matrix( matrix )


def transpose_matrix( matrix ):
    transposedMatrix = [[matrix[j][i] for j in range(len(matrix))] for i in range(len(matrix[0]))]
    return transposedMatrix

# This method will only work for square matrices
def convert_1D_to_2D_array( size , arr ):
    result = []
    for i in range( size ):
        new = arr [ size * i : size * ( i + 1 ) ]
        result.append( new )
    return result

def print_BitVector_2d_array( bv ):
    
    print([ [ item.getHexStringFromBitVector().zfill(2) for item in obj ] for obj in bv ] )



def multiply_bv( bv1 , bv2 ):
    return bv1.gf_multiply_modular(bv2, AES_modulus, 8)



def add_bv( bvList ):
    tempList = [item for item in bvList]
    total = BitVector(intVal=0, size=8)
    
    for i in range(len(tempList)):
        total ^= tempList[i]
    return total


def unpack_list( *bvList ):
    result = []
    for i in bvList:
        result += i
    return result


##############################################################################################################################

# KEY SECTION

def generate_round_constant(rounds):
    bv1 = BitVector(hexstring="01")
    bv2 = BitVector(hexstring="02")

    roundConstant = bv1

    for round in range(rounds - 1):
        roundConstant = bv1.gf_multiply_modular( bv2, AES_modulus, 8 )  # returns a bitvector object
        bv1 = roundConstant
    return roundConstant


def generate_g(array, rounds):
    # Circular byte left shift the list:
    returnArr = deque(array)
    returnArr.rotate(-1)

    # Byte substitution using ( S-Box ):
    returnArr = [BitVector(intVal=Sbox[item.intValue()], size=8)
                 for item in returnArr]

    # Adding round constant:
    roundConstant = generate_round_constant(rounds)
    returnArr[0] ^= roundConstant

    return returnArr

def expand_key(initialWord, roundNo):
    w = initialWord

    gArray = generate_g(w[4 * roundNo - 1], roundNo)

    roundKey = []
    for i in range(4 * roundNo, 4 * roundNo + 4):
        newWord = []
        if i % 4 == 0:
            for itemW, itemG in zip(w[4 * roundNo - 4], gArray):
                newWord.append(itemW ^ itemG)
        else:
            for itemW1, itemW2 in zip(w[i - 1], w[i - 4]):
                newWord.append(itemW1 ^ itemW2)  # xor between w
        w.append(newWord)
        roundKey += newWord

    return w, roundKey

def generate_all_keys( key ):
    # Start the timer for this function
    startTime = datetime.datetime.now()

    # Generating the key for Round - 0:
    convertedKeyMatrix = convert_to_matrix(key, 'key')
    roundKeys = []
    firstKey = []


    for i in range(len(convertedKeyMatrix)):
        firstKey += convertedKeyMatrix[i]

    roundKeys.append(firstKey)

    # Generating keys for all 10 rounds:
    for round in range(1, 11):

        w, tempKey = expand_key(convertedKeyMatrix, round)
        roundKeys.append(tempKey)
        convertedKeyMatrix = w
    
    # Timer stops here
    keySchedulingTime = ( datetime.datetime.now() - startTime )

    return roundKeys , keySchedulingTime



##############################################################################################################################





# ENCRYPTION FUNCTIONS

def substitute_bytes(stateMatrix):
    substitutedMatrix = [[BitVector(intVal=Sbox[item.intValue()], size=8)
                     for item in obj] for obj in stateMatrix]

    return substitutedMatrix




def shift_row(substituedMatrix):
    shiftedMatrix = [substituedMatrix[0]]

    for i in range(1, len(substituedMatrix)):
        temp = deque(substituedMatrix[i])
        temp.rotate(-i)
        shiftedMatrix.append(temp)

    return shiftedMatrix



def mix_column(shiftedMatrix):
    # Using * as an operator on list unpacks the argument
    mixedMatrix = [[add_bv(multiply_bv(a, b) for a, b in zip(Mixer_row, shiftedMatrix_col))
                    for shiftedMatrix_col in zip(*shiftedMatrix)] for Mixer_row in Mixer]
    return mixedMatrix




def encrypt( plainText , roundKeys , decode ):
    
    convertedPlainText = convert_to_matrix( plainText.decode(decode, 'ignore') , 'plain' )
    convertedKeyMatrix = transpose_matrix( convert_1D_to_2D_array( 4 , roundKeys[0] ) )

    # For Round - 0:

    # Adding State Matrix & Round-0 key:
    stateMatrix = add_round_key(convertedPlainText, convertedKeyMatrix )
    
    # For Round - 1 -> 10 :
    # !! for round 10 we skip mixed column
    for round in range(1, 11):
        substitutedMatrix = substitute_bytes(stateMatrix)
        shiftedMatrix = shift_row(substitutedMatrix)
        if round < 10:
            mixedMatrix = mix_column(shiftedMatrix)
        else:
            mixedMatrix = shiftedMatrix
        roundKeyMatrix = convert_1D_to_2D_array(4,  roundKeys[round])
        stateMatrix = add_round_key(mixedMatrix, transpose_matrix(
            roundKeyMatrix))  # need to transpose the key

    stateMatrix = transpose_matrix(stateMatrix)
    cipherText = []
    [cipherText := cipherText + item for item in stateMatrix]

    
    return cipherText



def encrypt_file( plainText , roundKeys , decode ):

    # Start the timer for this function
    startTime = datetime.datetime.now()

    # Only taking 16 characters at a time for the plaintext
    chunks, chunk_size = len(plainText), 16
    texts = [plainText[i:i+chunk_size] for i in range(0, chunks, chunk_size)]
    paddingSpace = 0

    if len(texts[len(texts) - 1]) < 16:
        paddingSpace = 16 - len(texts[len(texts) - 1])

    cipherTexts = [ encrypt( text , roundKeys , decode ) for text in texts ]

    # print_BitVector_2d_array( cipherTexts )
    singleCipherText = unpack_list(*cipherTexts)

    cipherTextInHex = ''.join(
        [item.getHexStringFromBitVector() for item in singleCipherText])
    cipherTextInASCII = ''.join(
        [item.getTextFromBitVector() for item in singleCipherText])

    encryptionTime = datetime.datetime.now() - startTime 
    return cipherTextInASCII, cipherTextInHex, paddingSpace , encryptionTime


##############################################################################################################################

# DECRYPTION SECTION

def inverse_mix_column( addedMatrix ):
    # Using * as an operator on list unpacks the argument
    mixedMatrix = [[ add_bv( multiply_bv(a,b) for a,b in zip( Mixer_row,addedMatrix_col ) )  for addedMatrix_col in zip(*addedMatrix)] for Mixer_row in InvMixer]
    return mixedMatrix




def inverse_substitute_bytes(shiftedMatrix):
    substitutedMatrix = [ [ BitVector(intVal=InvSbox[item.intValue()], size=8) for item in obj ] for obj in shiftedMatrix ]

    return substitutedMatrix




def inverse_shift_row( stateMatrix ):
    shiftedMatrix = [stateMatrix[0]]
    
    for i in range( 1 , len( stateMatrix ) ):
        temp = deque( stateMatrix[i] )
        temp.rotate(i)
        shiftedMatrix.append( temp )
          
    return shiftedMatrix




def decrypt( cipherText , roundKeys , decode ):

    inversedRoundKeys = [ ele for ele in reversed(roundKeys)]

    convertedCipherText = convert_to_matrix( cipherText , 'plain' )
    convertedKeyMatrix = transpose_matrix( convert_1D_to_2D_array( 4 , inversedRoundKeys[0] ) )

    # For Round - 0:

    # Adding State Matrix & Round-0 key:
    stateMatrix = add_round_key( convertedCipherText , convertedKeyMatrix )

    # For Round - 1 -> 10
    # !! for round 10 we skip inversed mixed column
    for round in range( 1 , 11 ):
        shiftedMatrix = inverse_shift_row( stateMatrix )
        substitutedMatrix = inverse_substitute_bytes( shiftedMatrix )
        inversedRoundKeyMatrix = convert_1D_to_2D_array( 4 , inversedRoundKeys[ round ] )
        addedMatrix = add_round_key( substitutedMatrix , transpose_matrix(inversedRoundKeyMatrix) )
        
        stateMatrix = ( round < 10 ) and inverse_mix_column( addedMatrix ) or addedMatrix

        # print( "Here in Loop:- " , round )
        # print_BitVector_2d_array( stateMatrix )

    stateMatrix = transpose_matrix( stateMatrix )
    plainText = []
    [plainText := plainText + item for item in stateMatrix ]

    
    return plainText 



def decrypt_file( cipherText , roundKeys , decode ):
    # Timer started for this function
    start_time = datetime.datetime.now()

    chunks, chunk_size = len(cipherText), 16 
    texts = [ cipherText[i:i+chunk_size] for i in range(0, chunks, chunk_size) ]


    plainTexts = [ decrypt( text , roundKeys , decode ) for text in texts ]

    plainText = unpack_list( *plainTexts )

    plainTextInHex = ''.join([item.getHexStringFromBitVector() for item in plainText ])
    plainTextInASCII = ''.join( [item.getTextFromBitVector() for item in plainText ] )

    decryptionTime = datetime.datetime.now() - start_time 
    return plainTextInASCII , plainTextInHex , decryptionTime


##############################################################################################################################


def main():
   
    code = 'utf-8'

    #Input for Encryption
    choice = input('''Input your choice:
    1) Encrypt & Decrypt Text
    2) Encrypt & Decrypt PDF
    3) Encrypt & Decrypt Image\n''')
    key = input("\nInput your key -> ")

    # Generate all round keys
    roundKeys, keySchedulingTime = generate_all_keys( key )
    
    if choice == '1':
        
        # Encryption section

        plainText = bytes(input("Input your text:[press enter to skip] ->  "), code )

        if len(plainText) == 0:
            with open("demofile.txt", "rb" ) as f:
                plainText = f.read()
        
        cipherText, cipherTextInHex, paddingSpace, encryptionTime = encrypt_file( plainText , roundKeys , code)

        # print("Cipher Text: \n[In Hex] : ", cipherTextInHex)
        # print("[In ASCII]: ", cipherText)

        with open('encryptedTextFile.txt', 'w' , encoding=code) as f:
            f.writelines(cipherText + "," + str(paddingSpace))
        

        # Decryption Section
        f = open("encryptedTextFile.txt", "rb")
        cipherText = f.read().decode(code)

        position = cipherText.rfind(',')
        text = cipherText[:position]
        paddingSpace = cipherText[position + 1: len(cipherText)]


        plainText, plainTextInHex, decryptionTime = decrypt_file( text , roundKeys , code )

        # removing the extra space added to have 16 chars
        plainText = (int(paddingSpace) !=
                     0) and plainText[:-int(paddingSpace)] or plainText


        print("\n\nDeciphered Text: \n[In Hex] : ", plainTextInHex)
        print("[In ASCII] : ", plainText)
        print("Length of the text : ", len(plainText))

    elif choice == '2':
        pdfFile = open('demofile.pdf' , 'rb')

        pdfReader = PyPDF2.PdfFileReader( pdfFile )

        plainText = ''

        for i in range( pdfReader.numPages ):
            pageObj = pdfReader.getPage(i)
            plainText += pageObj.extractText()

        
        pdfFile.close()


        cipherText, cipherTextInHex, paddingSpace, encryptionTime = encrypt_file( bytes(plainText,code) , roundKeys , code)
        
        with open('encryptedTextFile.txt', 'w' , encoding=code) as f:
            f.writelines(cipherText + "," + str(paddingSpace))

        
        # Decryption Section
        f = open("encryptedTextFile.txt", "rb")
        cipherText = f.read().decode(code)

        position = cipherText.rfind(',')
        text = cipherText[:position]
        paddingSpace = cipherText[position + 1: len(cipherText)]


        plainText, plainTextInHex, decryptionTime = decrypt_file( text , roundKeys , code )

        # removing the extra space added to have 16 chars
        plainText = (int(paddingSpace) !=
                     0) and plainText[:-int(paddingSpace)] or plainText

        print("\n\nDeciphered Text: \n[In Hex] : ", plainTextInHex)
        print("[In ASCII] : ", plainText)
        print("Length of the text : ", len(plainText))
    
    elif choice == '3':
        with open('syed.jpg', 'rb' ) as f:
            content = f.read()

        

        plainText = binascii.hexlify(content).decode('mac_roman')

        cipherText, cipherTextInHex, paddingSpace, encryptionTime = encrypt_file( bytes(plainText,code) , roundKeys , code )

        with open('encryptedTextFile.txt', 'w' , encoding='utf-8', errors='ignore') as f:
            f.writelines(cipherText + "," + str(paddingSpace))

        
        # Decryption Section
        f = open("encryptedTextFile.txt", "rb")
        cipherText = f.read().decode(code)

        position = cipherText.rfind(',')
        text = cipherText[:position]
        paddingSpace = cipherText[position + 1: len(cipherText)]


        plainText, plainTextInHex, decryptionTime = decrypt_file( text , roundKeys , code )

        # removing the extra space added to have 16 chars
        plainText = (int(paddingSpace) !=
                     0) and plainText[:-int(paddingSpace)] or plainText

        returnedImage = bytes(plainText)

        with open( "outputImage" , 'wb' ) as f:
            f.write( returnedImage )
        
        Image.open('outputImage').save('outputImage' + '.png', 'PNG')
        

        

    print("\n\nStats:")
    print("Key Scheduling Time: ", keySchedulingTime)
    print("Encryption-Time: ", encryptionTime)
    print("Decryption Time: ", decryptionTime)
    return




if __name__ == "__main__":
    main()
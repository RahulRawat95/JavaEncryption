import javax.crypto.Cipher ;
import java.security.SecureRandom ;
import javax.crypto.spec.GCMParameterSpec ;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.util.Base64 ;

import java.security.NoSuchAlgorithmException ;
import java.security.InvalidKeyException;
import javax.crypto.IllegalBlockSizeException ;
import javax.crypto.NoSuchPaddingException ;
import java.security.InvalidAlgorithmParameterException ;
import javax.crypto.BadPaddingException ;
import javax.crypto.ShortBufferException;


import java.security.SecureRandom ;
import javax.crypto.spec.PBEKeySpec ;
import javax.crypto.SecretKeyFactory ;
import javax.crypto.spec.SecretKeySpec ;

import java.security.KeyPairGenerator;
import java.security.PrivateKey ;
import java.security.PublicKey ;
import java.lang.Exception ;
import java.security.Key ;
import java.security.KeyPair ;

import java.util.Base64 ;


import java.security.spec.InvalidKeySpecException ;
import java.lang.NullPointerException ;
import java.security.spec.InvalidKeySpecException ;
import java.lang.NullPointerException ;
import java.security.NoSuchAlgorithmException ;
import java.lang.IllegalArgumentException ;
import java.security.GeneralSecurityException ;

import java.util.Arrays ; 

/**
        This class shows how to securely perform AES encryption in GCM mode, with 256 bits key size.
*/
public class myencryption {

        public static int AES_KEY_SIZE = 256 ;
        public static int IV_SIZE = 96 ;
        public static int TAG_BIT_LENGTH = 128 ;
        public static String ALGO_TRANSFORMATION_STRING = "AES/GCM/PKCS5Padding" ;

        public static byte[] aesEncrypt(String message, SecretKey aesKey, GCMParameterSpec gcmParamSpec, byte[] aadData) {
                Cipher c = null ;

                try {
                        c = Cipher.getInstance(ALGO_TRANSFORMATION_STRING); // Transformation specifies algortihm, mode of operation and padding
                }catch(NoSuchAlgorithmException noSuchAlgoExc) {System.out.println("Exception while encrypting. Algorithm being requested is not available in this environment " + noSuchAlgoExc); System.exit(1); }
                 catch(NoSuchPaddingException noSuchPaddingExc) {System.out.println("Exception while encrypting. Padding Scheme being requested is not available this environment " + noSuchPaddingExc); System.exit(1); }

                
                try {
                    c.init(Cipher.ENCRYPT_MODE, aesKey, gcmParamSpec, new SecureRandom()) ;
                } catch(InvalidKeyException invalidKeyExc) {System.out.println("Exception while encrypting. Key being used is not valid. It could be due to invalid encoding, wrong length or uninitialized " + invalidKeyExc) ; System.exit(1); }
                 catch(InvalidAlgorithmParameterException invalidAlgoParamExc) {System.out.println("Exception while encrypting. Algorithm parameters being specified are not valid " + invalidAlgoParamExc) ; System.exit(1); }

               try { 
                    c.updateAAD(aadData) ; // add AAD tag data before encrypting
                }catch(IllegalArgumentException illegalArgumentExc) {System.out.println("Exception thrown while encrypting. Byte array might be null " +illegalArgumentExc ); System.exit(1);} 
                catch(IllegalStateException illegalStateExc) {System.out.println("Exception thrown while encrypting. CIpher is in an illegal state " +illegalStateExc); System.exit(1);} 
                catch(UnsupportedOperationException unsupportedExc) {System.out.println("Exception thrown while encrypting. Provider might not be supporting this method " +unsupportedExc); System.exit(1);} 
               
               byte[] cipherTextInByteArr = null ;
               try {
                    cipherTextInByteArr = c.doFinal(message.getBytes()) ;
               } catch(IllegalBlockSizeException illegalBlockSizeExc) {System.out.println("Exception while encrypting, due to block size " + illegalBlockSizeExc) ; System.exit(1); }
                 catch(BadPaddingException badPaddingExc) {System.out.println("Exception while encrypting, due to padding scheme " + badPaddingExc) ; System.exit(1); }

               return cipherTextInByteArr ;
        }


        public static byte[] aesDecrypt(byte[] encryptedMessage, SecretKey aesKey, GCMParameterSpec gcmParamSpec, byte[] aadData) {
               Cipher c = null ;
        
               try {
                   c = Cipher.getInstance(ALGO_TRANSFORMATION_STRING); // Transformation specifies algortihm, mode of operation and padding
                } catch(NoSuchAlgorithmException noSuchAlgoExc) {System.out.println("Exception while decrypting. Algorithm being requested is not available in environment " + noSuchAlgoExc); System.exit(1); }
                 catch(NoSuchPaddingException noSuchAlgoExc) {System.out.println("Exception while decrypting. Padding scheme being requested is not available in environment " + noSuchAlgoExc); System.exit(1); }  

                try {
                    c.init(Cipher.DECRYPT_MODE, aesKey, gcmParamSpec, new SecureRandom()) ;
                } catch(InvalidKeyException invalidKeyExc) {System.out.println("Exception while encrypting. Key being used is not valid. It could be due to invalid encoding, wrong length or uninitialized " + invalidKeyExc) ; System.exit(1); }
                 catch(InvalidAlgorithmParameterException invalidParamSpecExc) {System.out.println("Exception while encrypting. Algorithm Param being used is not valid. " + invalidParamSpecExc) ; System.exit(1); }

                try {
                    c.updateAAD(aadData) ; // Add AAD details before decrypting
                }catch(IllegalArgumentException illegalArgumentExc) {System.out.println("Exception thrown while encrypting. Byte array might be null " +illegalArgumentExc ); System.exit(1);}
                catch(IllegalStateException illegalStateExc) {System.out.println("Exception thrown while encrypting. CIpher is in an illegal state " +illegalStateExc); System.exit(1);}
                
                byte[] plainTextInByteArr = null ;
                try {
                    plainTextInByteArr = c.doFinal(encryptedMessage) ;
                } catch(IllegalBlockSizeException illegalBlockSizeExc) {System.out.println("Exception while decryption, due to block size " + illegalBlockSizeExc) ; System.exit(1); }
                 catch(BadPaddingException badPaddingExc) {System.out.println("Exception while decryption, due to padding scheme " + badPaddingExc) ; System.exit(1); }

                return plainTextInByteArr ;
        }

        public static String PDKDF_ALGORITHM = "PBKDF2WithHmacSHA512" ;
        public static int ITERATION_COUNT = 12288 ;
        public static int SALT_LENGTH = 128 ;
        public static int DERIVED_KEY_LENGTH = 32 ;

        public static byte[] computePBKDF(char[] password) throws GeneralSecurityException {
                byte[] salt = new byte[SALT_LENGTH] ;
                
                SecureRandom secRandom = new SecureRandom() ;
                secRandom.nextBytes(salt) ;

                PBEKeySpec keySpec = null ;
                try { 
                    keySpec = new PBEKeySpec(password, salt, ITERATION_COUNT , DERIVED_KEY_LENGTH * 8);
                } catch(NullPointerException nullPointerExc){throw new GeneralSecurityException("Salt " + salt + "is null") ;}  
                 catch(IllegalArgumentException illegalArgumentExc){throw new GeneralSecurityException("One of the argument is illegal. Salt " + salt + " is of 0 length, iteration count " + ITERATION_COUNT + " is not positive or derived key length " + DERIVED_KEY_LENGTH + " is not positive." ) ;}  

                SecretKeyFactory pbkdfKeyFactory = null ;

                try { 
                    pbkdfKeyFactory = SecretKeyFactory.getInstance(PDKDF_ALGORITHM) ;
                } catch(NullPointerException nullPointExc) {throw new GeneralSecurityException("Specified algorithm " + PDKDF_ALGORITHM  + "is null") ;} 
                 catch(NoSuchAlgorithmException noSuchAlgoExc) {throw new GeneralSecurityException("Specified algorithm " + PDKDF_ALGORITHM + "is not available by the provider " + pbkdfKeyFactory.getProvider().getName()) ;} 
      
                byte[] pbkdfHashedArray = null ; 
                try {  
                    pbkdfHashedArray = pbkdfKeyFactory.generateSecret(keySpec).getEncoded() ; 
                } catch(InvalidKeySpecException invalidKeyExc) {throw new GeneralSecurityException("Specified key specification is inappropriate") ; } 
               
                return pbkdfHashedArray ; 
        }
		
		static int RSA_KEY_LENGTH = 4096;
        static String ALGORITHM_NAME = "RSA" ;
        static String PADDING_SCHEME = "OAEPWITHSHA-512ANDMGF1PADDING" ;
        static String MODE_OF_OPERATION = "ECB" ; // This essentially means none behind the scene
		
		public static String rsaEncrypt(String message, Key publicKey) throws Exception {
        
                Cipher c = Cipher.getInstance(ALGORITHM_NAME + "/" + MODE_OF_OPERATION + "/" + PADDING_SCHEME) ;

                c.init(Cipher.ENCRYPT_MODE, publicKey) ;

                byte[] cipherTextArray = c.doFinal(message.getBytes()) ;

                return Base64.getEncoder().encodeToString(cipherTextArray) ;
                
        }


        public static String rsaDecrypt(byte[] encryptedMessage, Key privateKey) throws Exception {
                Cipher c = Cipher.getInstance(ALGORITHM_NAME + "/" + MODE_OF_OPERATION + "/" + PADDING_SCHEME) ;
                c.init(Cipher.DECRYPT_MODE, privateKey);
                byte[] plainText = c.doFinal(encryptedMessage);

                return new String(plainText) ;

        }
		
		public static String get(){
			RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
			return publicKey.getModulus().toString() + "|" + publicKey.getPublicExponent().toString();
		}
		
		public static RSAPublicKeySpec get(){
			String []Parts = MyKeyString.split("\\|");
			RSAPublicKeySpec Spec = new RSAPublicKeySpec(new BigInteger(Parts[0]),new BigInteger(Parts[1]));
			return KeyFactory.getInstance("RSA").generatePublic(Spec);
		}
		
		public static void main(String args[]) {

				String shortMessage = args[1] ;

                try {

                // Generate Key Pairs
                KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance(ALGORITHM_NAME) ;
                rsaKeyGen.initialize(RSA_KEY_LENGTH) ;
                KeyPair rsaKeyPair = rsaKeyGen.generateKeyPair() ;


                    String encryptedText = rsaEncrypt(shortMessage, rsaKeyPair.getPublic());

                    String decryptedText = rsaDecrypt(Base64.getDecoder().decode(encryptedText), rsaKeyPair.getPrivate()) ;

                    System.out.println("Encrypted text = " + encryptedText) ;
                    System.out.println("Decrypted text = " + decryptedText) ;

                } catch(Exception e) {System.out.println("Exception while encryption/decryption") ;e.printStackTrace() ; } 
		
                // Strings are immutatable, so there is no way to change/nullify/modify its content after use. So always, collect and store security sensitive information in a char array instead. 
                char[] PASSWORD = args[0].toCharArray() ; 

                byte[] hashedPassword = null ;
                try {  
                    hashedPassword = computePBKDF(PASSWORD) ;                
                } catch(GeneralSecurityException genSecExc) {System.out.println(genSecExc.getMessage() + " " + genSecExc.getCause() ) ; System.exit(1) ; } 
                
				System.out.println("password hash = "+Base64.getEncoder().encodeToString(hashedPassword));
				
				String messageToEncrypt = args[1] ;
                
                byte[] aadData = "random".getBytes() ; // Any random data can be used as tag. Some common examples could be domain name...

                // Use different key+IV pair for encrypting/decrypting different parameters

                // Generating Key
                SecretKey aesKey = new SecretKeySpec(hashedPassword, "AES");
                /*try {
                    KeyGenerator keygen = KeyGenerator.getInstance("AES") ; // Specifying algorithm key will be used for 
                    keygen.init(AES_KEY_SIZE) ; // Specifying Key size to be used, Note: This would need JCE Unlimited Strength to be installed explicitly 
                    aesKey = keygen.generateKey() ;
                } catch(NoSuchAlgorithmException noSuchAlgoExc) { System.out.println("Key being request is for AES algorithm, but this cryptographic algorithm is not available in the environment "  + noSuchAlgoExc) ; System.exit(1) ; }*/

                // Generating IV
                byte iv[] = new byte[IV_SIZE];
                SecureRandom secRandom = new SecureRandom() ;
                secRandom.nextBytes(iv); // SecureRandom initialized using self-seeding
                

                // Initialize GCM Parameters
                GCMParameterSpec gcmParamSpec = new GCMParameterSpec(TAG_BIT_LENGTH, iv) ;      
                
                byte[] encryptedText = aesEncrypt(messageToEncrypt, aesKey,  gcmParamSpec, aadData) ;          
                
                System.out.println("Encrypted Text = " + Base64.getEncoder().encodeToString(encryptedText) ) ;

                byte[] decryptedText = aesDecrypt(encryptedText, aesKey, gcmParamSpec, aadData) ; // Same key, IV and GCM Specs for decryption as used for encryption.

                System.out.println("Decrypted text " + new String(decryptedText)) ;

                // Make sure not to repeat Key + IV pair, for encrypting more than one plaintext.
                secRandom.nextBytes(iv);
        }
}
#include <vector>
#include <iostream>
#include <string>
#include <typeinfo>
#include <chrono>


#include "../src/config.h"
#include "../src/SEAL_Cipher.h"
#include "../src/pasta_3_plain.h" // for PASTA_params
#include "../src/pasta_3_seal.h"
#include "../src/utils.h"
#include "../src/sealhelper.h"
#include "../openssl/rsa.h"

#include "../crypto++/cryptlib.h" // Crypto++ for the RSA
#include "../crypto++/rsa.h"
#include "../crypto++/osrng.h"
#include "../crypto++/base64.h"
#include "../crypto++/files.h"


using namespace std;
using namespace seal;


std::shared_ptr<seal::SEALContext> context;
struct User{
    vector<uint64_t> ssk;
};

struct CSP{
    std::vector<Ciphertext> CSP_HECipher;
    PublicKey he_publicKey;
    SecretKey he_secretKey;

};
//Represents the analyst
void analyst(std::vector<Ciphertext> EvalCiphers, PASTA_3_MODIFIED_1::PASTA_SEAL& pastaSealInstance){
    size_t total_decrypt_time = 0;  
    for (int i = 0; i < 1; i++){
        chrono::high_resolution_clock::time_point start1, end1;
        chrono::milliseconds diff1;

        //Time to decrypt
        start1 = chrono::high_resolution_clock::now();

        std::vector<uint64_t> dec = pastaSealInstance.decrypt_result(EvalCiphers, config::USE_BATCH);

        end1 = chrono::high_resolution_clock::now();
        diff1 = chrono::duration_cast<chrono::milliseconds>(end1 - start1);
        total_decrypt_time += diff1.count();

    }
    cout << "Total Decrypt result time: " << total_decrypt_time << endl;
    

}

//Respresents the server provider
void csp(std::vector<Ciphertext> enc_key,
 std::vector<uint64_t> cipherData,PASTA_3_MODIFIED_1::PASTA_SEAL& pastaSealInstance){

    size_t total_decomposition_time = 0;  
    size_t total_eval_time = 0;
    Ciphertext RandomCipher;
    for (int i = 0; i < 1; i++){
        Evaluator analyst_he_eval(*context);
        chrono::high_resolution_clock::time_point start1, start2, end1, end2;
        chrono::milliseconds diff1, diff2;

        //Time Decomposition
        start1 = chrono::high_resolution_clock::now();

        CSP csp;
        std::vector<Ciphertext> HECipher = pastaSealInstance.decomposition(cipherData, enc_key,config::USE_BATCH);
        csp.CSP_HECipher = HECipher;

        end1 = chrono::high_resolution_clock::now();
        diff1 = chrono::duration_cast<chrono::milliseconds>(end1 - start1);
        total_decomposition_time += diff1.count();

        //Time EVAL
        start2 = chrono::high_resolution_clock::now();
        
        packed_enc_multiply(HECipher[0],HECipher[0],RandomCipher, analyst_he_eval);
        end2 = chrono::high_resolution_clock::now();

        diff2 = chrono::duration_cast<chrono::milliseconds>(end2 - start2);

        total_eval_time += diff2.count();
        if (i == 50 or i == 100 or i == 150){
            cout << "Total Decomposition time: " << total_decomposition_time << " : " << i << endl;
            cout << "Total Eval time: " << total_eval_time << " : " << i << endl; 
        }
        

    }
    cout << "Total Decomposition time: " << total_decomposition_time << endl;
    cout << "Total Eval time: " << total_eval_time << endl;

    std::vector<Ciphertext> EvalCiphers = {RandomCipher};
    analyst(EvalCiphers, pastaSealInstance);

    //Send cipher to analyst
    

}

//Represents the user
void client(vector<uint64_t> ssk, PASTA_3_MODIFIED_1::PASTA_SEAL& pastaSealInstance){
    chrono::high_resolution_clock::time_point start1, start2, start3, end1, end2, end3;
    chrono::milliseconds diff1, diff2, diff3;


    size_t total_symmetric_enc_time = 0;  
    size_t total_key_enc_time = 0;
    size_t total_only_HE_time = 0;


    std::vector<uint64_t> cipherData;
    std::vector<Ciphertext> enc_key;
    for (int i = 0; i < 1; i++){

        //Time symmetric encryptio
        start1 = chrono::high_resolution_clock::now();
        PASTA_3_MODIFIED_1::PASTA Symmetric_Encryptor(ssk, config::plain_mod);
        vector<uint64_t> userData = create_random_vector(4);
        
        cipherData = Symmetric_Encryptor.encrypt(userData);
        end1 = chrono::high_resolution_clock::now();

        diff1 = chrono::duration_cast<chrono::milliseconds>(end1 - start1);
        total_symmetric_enc_time += diff1.count(); 
        

        //Encryt user data with HE and the time it takes
        start3 = chrono::high_resolution_clock::now();
        
        enc_key = pastaSealInstance.encrypt_key_2(userData, config::USE_BATCH);
        
        end3 = chrono::high_resolution_clock::now();
        diff3 = chrono::duration_cast<chrono::milliseconds>(end3 - start3);
        total_only_HE_time += diff3.count();
        
        

    }
    
    //Time to HE for symmetric key
    start2 = chrono::high_resolution_clock::now();

        
    enc_key = pastaSealInstance.encrypt_key_2(ssk, config::USE_BATCH);
    
    end2 = chrono::high_resolution_clock::now();
    diff2 = chrono::duration_cast<chrono::milliseconds>(end2 - start2);
    total_key_enc_time += diff2.count();


    cout << "Total symmetric encryption time: " << total_symmetric_enc_time / 1 << endl;
    cout << "Total key encryption time: " << total_key_enc_time / 1 << endl;
    cout << "Total HE time: " << total_only_HE_time / 1 << endl;
    //Call CSP with enc_key and cipher data
    csp(enc_key, cipherData, pastaSealInstance);

    
    

    

}



int main(){

    User user;
    CSP csp;
    chrono::high_resolution_clock::time_point start1, start2, start3, start4, end1, end2, end3, end4;
    chrono::milliseconds diff1, diff2, diff3, diff4;

    //Create the encryotion parametres
    EncryptionParameters params(scheme_type::bfv);
    size_t pol_mod_degree = 16384;
    params.set_poly_modulus_degree(pol_mod_degree);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(pol_mod_degree));
    params.set_plain_modulus(65537);
    
    seal::sec_level_type sec = seal::sec_level_type::tc128;
    context = std::make_shared<seal::SEALContext>(params, true, sec);

    //Time the RSA key generation
    start1 = chrono::high_resolution_clock::now();
    CryptoPP::AutoSeededRandomPool rng;
    // Create private key
    CryptoPP::InvertibleRSAFunction privKey;
    privKey.Initialize(rng, 2048);

    // Create public key
    CryptoPP::RSAFunction pubKey(privKey);


    
    end1 = chrono::high_resolution_clock::now();
    diff1 = chrono::duration_cast<chrono::milliseconds>(end1 - start1);


    //Some HE keys for CSP    
    KeyGenerator csp_keygen(*context);
    SecretKey CSP_secret_key = csp_keygen.secret_key();
    PublicKey CSP_public_key;

    csp_keygen.create_public_key(CSP_public_key);
    
    csp.he_publicKey = CSP_public_key;
    csp.he_secretKey = CSP_secret_key;
    Encryptor CSP_encryptor(*context, CSP_public_key);


    //Analys HE keygen
    start2 = chrono::high_resolution_clock::now();
    KeyGenerator analyst_keygen(*context);
    SecretKey analys_he_secret_key = analyst_keygen.secret_key();
    PublicKey analyst_he_public_key;
    RelinKeys analyst_he_relin_keys;
    GaloisKeys analyst_he_galois_keys;
    
    analyst_keygen.create_public_key(analyst_he_public_key);
    analyst_keygen.create_relin_keys(analyst_he_relin_keys);

    
    BatchEncoder analyst_he_benc(*context);
    Encryptor analyst_he_enc(*context, analyst_he_public_key);
    Evaluator analyst_he_eval(*context);

    
    end2 = chrono::high_resolution_clock::now();
    vector<int> gk_indices = add_gk_indices(false, analyst_he_benc);
    analyst_keygen.create_galois_keys(gk_indices, analyst_he_galois_keys); 
    
    diff2 = chrono::duration_cast<chrono::milliseconds>(end2 - start2);

    cout << "RSA KeyPair: " << diff1.count() << "\n" << "ANALYST: " << diff2.count() << endl;  


    //Decryption message and encryptin it
    vector<int64_t> key_input = {1,5,8,3};
    start3 = chrono::high_resolution_clock::now();
    Ciphertext cipher_txt = encrypting(key_input, CSP_public_key, analyst_he_benc, analyst_he_enc);
    end3 = chrono::high_resolution_clock::now();
    diff3 = chrono::duration_cast<chrono::milliseconds>(end3 - start3);

    cout << "encryption time: " << diff3.count() << endl; 

    start4 = chrono::high_resolution_clock::now();
    vector<int64_t> decrypted_key_input = decrypting(cipher_txt, CSP_secret_key, analyst_he_benc, *context, key_input.size());
    end4 = chrono::high_resolution_clock::now();

    diff4 = chrono::duration_cast<chrono::milliseconds>(end4 - start4);

    cout << "decryption time: " << diff4.count() << endl; 

    //Symmetric key for user
    vector<uint64_t> s_secret_key = get_symmetric_key();
    user.ssk = s_secret_key;
    PASTA_3_MODIFIED_1::PASTA_SEAL pastaSealInstance(context, analyst_he_public_key, CSP_secret_key,
    analyst_he_relin_keys, analyst_he_galois_keys);

    //Call the user with ssk
    client(s_secret_key, pastaSealInstance);
    return 0;
}





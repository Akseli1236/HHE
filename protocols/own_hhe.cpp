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
    Ciphertext dummy;

};
struct AnalystData {  
    vector<int64_t> w{17, 31, 24, 17};  // dummy weights
    vector<int64_t> b{-5, -5, -5, -5};  // dummy biases
    Ciphertext w_c;  // the encrypted weights
    Ciphertext b_c;  // the encrypted biases
    PublicKey he_pk;
    SecretKey he_sk;
    RelinKeys he_rk;
    GaloisKeys he_gk;
    stringstream pk_stream;
    stringstream rk_stream;
    stringstream gk_stream;
    stringstream cipher1_stream;
    stringstream cipher2_stream;
};

void analyst(std::vector<Ciphertext> EvalCiphers, PASTA_3_MODIFIED_1::PASTA_SEAL& pastaSealInstance){

    chrono::high_resolution_clock::time_point start1, start2, end1, end2;
    chrono::milliseconds diff1, diff2;
    start1 = chrono::high_resolution_clock::now();

    std::vector<uint64_t> dec = pastaSealInstance.decrypt_result(EvalCiphers, config::USE_BATCH);

    end1 = chrono::high_resolution_clock::now();
    diff1 = chrono::duration_cast<chrono::milliseconds>(end1 - start1);

    cout << "Decrypt result time: " << diff1.count() << endl;
    //CSP csp;
    //AnalystD anal;
    

     //csp.dummy = encrypting(anal.analyst_he_relin_keys, anal.analyst_he_public_key, anal.analyst_he_benc, anal.analyst_he_enc);
    

}

void csp(std::vector<Ciphertext> enc_key,
 std::vector<uint64_t> cipherData,PASTA_3_MODIFIED_1::PASTA_SEAL& pastaSealInstance){
    Evaluator analyst_he_eval(*context);
    chrono::high_resolution_clock::time_point start1, start2, end1, end2;
    chrono::milliseconds diff1, diff2;

    start1 = chrono::high_resolution_clock::now();

    CSP csp;
    std::vector<Ciphertext> HECipher = pastaSealInstance.decomposition(cipherData, enc_key,config::USE_BATCH);
    csp.CSP_HECipher = HECipher;

    end1 = chrono::high_resolution_clock::now();
    diff1 = chrono::duration_cast<chrono::milliseconds>(end1 - start1);
    cout << "Size: " << HECipher.size() << endl;
    cout << "DECOMP time: " << diff1.count() << endl;

    start2 = chrono::high_resolution_clock::now();
    Ciphertext RandomCipher;
    packed_enc_multiply(HECipher[0],HECipher[0],RandomCipher, analyst_he_eval);
    end2 = chrono::high_resolution_clock::now();

    diff2 = chrono::duration_cast<chrono::milliseconds>(end2 - start2);

    cout << "EVAL time: " << diff2.count() << endl;
    std::vector<Ciphertext> EvalCiphers = {RandomCipher};
    analyst(EvalCiphers, pastaSealInstance);

}

void client(vector<uint64_t> ssk, PASTA_3_MODIFIED_1::PASTA_SEAL& pastaSealInstance){
    chrono::high_resolution_clock::time_point start1, start2, end1, end2;
    chrono::milliseconds diff1, diff2;

    start1 = chrono::high_resolution_clock::now();
    PASTA_3_MODIFIED_1::PASTA Symmetric_Encryptor(ssk, config::plain_mod);
    std::vector<uint64_t> userData = {1,2,3,4,5,6};
    std::vector<uint64_t> cipherData;
    cipherData = Symmetric_Encryptor.encrypt(userData);
    end1 = chrono::high_resolution_clock::now();

    diff1 = chrono::duration_cast<chrono::milliseconds>(end1 - start1); 

    start2 = chrono::high_resolution_clock::now();

    
    std::vector<Ciphertext> enc_key = pastaSealInstance.encrypt_key_2(ssk, config::USE_BATCH);
    
    end2 = chrono::high_resolution_clock::now();
    diff2 = chrono::duration_cast<chrono::milliseconds>(end2 - start2);
    
    cout << "Symmetric encryption: " <<  diff1.count() << "\n" << "HE encryption: " << diff2.count() << endl;
    csp(enc_key, cipherData, pastaSealInstance);

    
    //BatchEncoder analyst_he_benc(*context);
    //Encryptor analyst_he_enc(*context, analyst_he_public_key);
    //auto encrypted_key = encrypt_symmetric_key(ssk, config::USE_BATCH, analyst_he_benc, analyst_he_enc);
    

}



int main(){
    User user;
    CSP csp;
    AnalystData Anal1;
    chrono::high_resolution_clock::time_point start1, start2, start3, end1, end2, end3;
    chrono::milliseconds diff1, diff2, diff3;
    EncryptionParameters params(scheme_type::bfv);
    size_t pol_mod_degree = 16384;
    params.set_poly_modulus_degree(pol_mod_degree);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(pol_mod_degree));
    params.set_plain_modulus(65537);
    
    seal::sec_level_type sec = seal::sec_level_type::tc128;
    context = std::make_shared<seal::SEALContext>(params, true, sec);

    start1 = chrono::high_resolution_clock::now();
    KeyGenerator csp_keygen(*context);
    SecretKey CSP_secret_key = csp_keygen.secret_key();
    PublicKey CSP_public_key;

    csp_keygen.create_public_key(CSP_public_key);
    
    csp.he_publicKey = CSP_public_key;
    csp.he_secretKey = CSP_secret_key;

    end1 = chrono::high_resolution_clock::now();
    diff1 = chrono::duration_cast<chrono::milliseconds>(end1 - start1); 


    
    start2 = chrono::high_resolution_clock::now();
    KeyGenerator analyst_keygen(*context);
    SecretKey analys_he_secret_key = analyst_keygen.secret_key();
    PublicKey analyst_he_public_key;
    RelinKeys analyst_he_relin_keys;
    GaloisKeys analyst_he_galois_keys;
    
    analyst_keygen.create_public_key(analyst_he_public_key);
    analyst_keygen.create_relin_keys(analyst_he_relin_keys);
    
                                      //HHE Decryption Secret Key                               //HHE RelinKey
    
    BatchEncoder analyst_he_benc(*context);
    Encryptor analyst_he_enc(*context, analyst_he_public_key);
    Evaluator analyst_he_eval(*context);

    
    end2 = chrono::high_resolution_clock::now();
    vector<int> gk_indices = add_gk_indices(false, analyst_he_benc);
    analyst_keygen.create_galois_keys(gk_indices, analyst_he_galois_keys); 
    
    diff2 = chrono::duration_cast<chrono::milliseconds>(end2 - start2);

    cout << "CSPKEYGEN: " << diff1.count() << "\n" << "ANALYST: " << diff2.count() << endl;  

    vector<uint64_t> s_secret_key = get_symmetric_key();
    user.ssk = s_secret_key;
    PASTA_3_MODIFIED_1::PASTA_SEAL pastaSealInstance(context, analyst_he_public_key, CSP_secret_key,
    analyst_he_relin_keys, analyst_he_galois_keys);
    client(s_secret_key, pastaSealInstance);
    //cout << "ssk.size() = " << s_secret_key.size() << endl;
    //print_vec(s_secret_key, s_secret_key.size(), "sk");
    return 0;
}





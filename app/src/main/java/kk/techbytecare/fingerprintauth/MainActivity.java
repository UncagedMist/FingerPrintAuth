package kk.techbytecare.fingerprintauth;

import android.app.KeyguardManager;
import android.hardware.fingerprint.FingerprintManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import kk.techbytecare.fingerprintauth.Helper.FingerPrintHelper;

public class MainActivity extends AppCompatActivity {

    private KeyStore keyStore;
    private static final String KEY_NAME = "TBC_KK";
    private Cipher cipher;
    private TextView textView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        KeyguardManager keyguardManager = (KeyguardManager)getSystemService(KEYGUARD_SERVICE);

        FingerprintManager fingerprintManager = (FingerprintManager)getSystemService(FINGERPRINT_SERVICE);

        if (!fingerprintManager.isHardwareDetected())   {
            Toast.makeText(this, "Fingerprint permission not enable..", Toast.LENGTH_SHORT).show();
        }
        else    {
            if (!fingerprintManager.hasEnrolledFingerprints())  {
                Toast.makeText(this, "Register at least one fingerprint in Setting", Toast.LENGTH_SHORT).show();
            }
            else    {
                if (!keyguardManager.isKeyguardSecure())    {
                    Toast.makeText(this, "lock screen security not enabled in setting", Toast.LENGTH_SHORT).show();
                }
                else    {
                    genKey();
                }

                if (cipherInit())   {
                    FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);
                    FingerPrintHelper helper =  new FingerPrintHelper(this);
                    helper.startAuthentication(fingerprintManager,cryptoObject);
                }
            }
        }
    }

    private boolean cipherInit() {

        try {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES+"/"
                    +KeyProperties.BLOCK_MODE_CBC+"/"+KeyProperties.ENCRYPTION_PADDING_PKCS7);

        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }

        try {
            keyStore.load(null);
            SecretKey key = (SecretKey)keyStore.getKey(KEY_NAME,null);
            cipher.init(Cipher.ENCRYPT_MODE,key);
            return true;
        }
        catch (IOException | CertificateException | KeyStoreException | InvalidKeyException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
            return false;
        }
    }

    private void genKey() {
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");

        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        KeyGenerator keyGenerator = null;

        try {
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }

        try {
            keyStore.load(null);

            keyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC).setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());

            keyGenerator.generateKey();

        } catch (IOException | CertificateException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

    }
}

package com.wavesplatform.zwaves.bls12;

import org.junit.Test;
import static org.junit.Assert.*;

import java.util.Base64;

public class Groth16Test {


    @Test
    public void test() {

        byte[] vk = Base64.getDecoder().decode("hwk883gUlTKCyXYA6XWZa8H9/xKIYZaJ0xEs0M5hQOMxiGpxocuX/8maSDmeCk3bo5ViaDBdO7ZBxAhLSe5k/5TFQyF5Lv7KN2tLKnwgoWMqB16OL8WdbePIwTCuPtJNAFKoTZylLDbSf02kckMcZQDPF9iGh+JC99Pio74vDpwTEjUx5tQ99gNQwxULtztsqDRsPnEvKvLmsxHt8LQVBkEBm2PBJFY+OXf1MNW021viDBpR10mX4WQ6zrsGL5L0GY4cwf4tlbh+Obit+LnN/SQTnREf8fPpdKZ1sa/ui3pGi8lMT6io4D7Ujlwx2RdCkBF+isfMf77HCEGsZANw0hSrO2FGg14Sl26xLAIohdaW8O7gEaag8JdVAZ3OVLd5Df1NkZBEr753Xb8WwaXsJjE7qxwINL1KdqA4+EiYW4edb7+a9bbBeOPtb67ZxmFqgyTNS/4obxahezNkjk00ytswsENg//Ee6dWBJZyLH+QGsaU2jO/W4WvRyZhmKKPdipOhiz4Rlrd2XYgsfHsfWf5v4GOTL+13ZB24dW1/m39n2woJ+v686fXbNW85XP/r");
        byte[] proof = Base64.getDecoder().decode("lvQLU/KqgFhsLkt/5C/scqs7nWR+eYtyPdWiLVBux9GblT4AhHYMdCgwQfSJcudvsgV6fXoK+DUSRgJ++Nqt+Wvb7GlYlHpxCysQhz26TTu8Nyo7zpmVPH92+UYmbvbQCSvX2BhWtvkfHmqDVjmSIQ4RUMfeveA1KZbSf999NE4qKK8Do+8oXcmTM4LZVmh1rlyqznIdFXPN7x3pD4E0gb6/y69xtWMChv9654FMg05bAdueKt9uA4BEcAbpkdHF");
        byte[] inputs = Base64.getDecoder().decode("LcMT3OOlkHLzJBKCKjjzzVMg+r+FVgd52LlhZPB4RFg=");

        byte[] inputs2 = Base64.getDecoder().decode("cmzVCcRVnckw3QUPhmG4Bkppeg4K50oDQwQ9EH+Fq1s=");
        byte[] inputs3 = {};

        assertTrue("Result should be true", Groth16.verify(vk, proof, inputs));
        assertFalse("Result should be false", Groth16.verify(vk, proof, inputs2));
        assertFalse("Result should be false", Groth16.verify(vk, proof, inputs3));        

    }

}
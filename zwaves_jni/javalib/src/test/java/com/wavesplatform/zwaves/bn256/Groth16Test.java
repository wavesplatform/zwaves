package com.wavesplatform.zwaves.bn256;

import org.junit.Test;

import java.util.Base64;

import static org.junit.Assert.*;

public class Groth16Test {
    @Test
    public void test() {
        byte[] vk = Base64.getDecoder().decode("LDCJzjgi5HtcHEXHfU8TZz+ZUHD2ZwsQ7JIEvzdMPYKYs9SoGkKUmg1yya4TE0Ms7x+KOJ4Ze/CPfKp2s5jbniFNM71N/YlHVbNkytLtQi1DzReSh9SNBsvskdY5mavQJe+67PuPVEYnx+lJ97qIG8243njZbGWPqUJ2Vqj49NAunhqX+eIkK3zAB3IPWls3gruzX2t9wrmyE9cVVvf1kgWx63PsQV37qdH0KcFRpCH89k4TPS6fLmqdFxX3YGHCGFTpr6tLogvjbUFJPT98kJ/xck0C0B/s8PTVKdao4VQHT4DBIO8+GB3CQVh6VV4EcMLtDWWNxF4yloAlKcFT0Q4AzJSimpFqd/SwSz9Pb7uk5srte3nwphVamC+fHlJt");
        byte[] proof = Base64.getDecoder().decode("GQPBoHuCPcIosF+WZKE5jZV13Ib4EdjLnABncpSHcMKBZl0LhllnPxcuzExIQwhxcfXvFFAjlnDGpKauQ9OQsjBKUBsdBZnGiV2Sg4TSdyHuLo2AbRRqJN0IV3iH3On8I4ngnL30ZAxVyGQH2EK58aUZGxMbbXGR9pQdh99QaiE=");
        byte[] inputs = Base64.getDecoder().decode("IfZhAypdtgvecKDWzVyRuvXatmFf2ZYcMWVkCJ0/MQo=");

        byte[] inputs2 = Base64.getDecoder().decode("cmzVCcRVnckw3QUPhmG4Bkppeg4K50oDQwQ9EH+Fq1s=");
        byte[] inputs3 = {};

        assertTrue("Result should be true", Groth16.verify(vk, proof, inputs));
        assertFalse("Result should be false", Groth16.verify(vk, proof, inputs2));
        assertFalse("Result should be false", Groth16.verify(vk, proof, inputs3));
    }
}

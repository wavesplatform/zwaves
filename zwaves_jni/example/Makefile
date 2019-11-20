java_run: lib
	javac Groth16.java && java -ea -Djava.library.path=../../target/release/ Groth16 && \
	    javac Bls12PedersenMerkleTree.java && java -ea -Djava.library.path=../../target/release/ Bls12PedersenMerkleTree

.PHONY: lib

javah:
	javah Bls12PedersenMerkleTree && javah Groth16

lib:
	cd .. && cargo +nightly build --release
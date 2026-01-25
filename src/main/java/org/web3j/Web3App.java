package org.web3j;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.Level;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.DynamicArray;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.gas.DefaultGasProvider;
import org.web3j.utils.Numeric;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.web3j.generated.contracts.FHECounter;
import org.web3j.kms.*;
import org.web3j.tools.*;

/**
 * <p>
 * This is the generated class for <code>web3j new helloworld</code>
 * </p>
 * <p>
 * It deploys the Hello World contract in src/main/solidity/ and prints its
 * address
 * </p>
 * <p>
 * For more information on how to run this project, please refer to our <a href=
 * "https://docs.web3j.io/latest/command_line_tools/#running-your-application">documentation</a>
 * </p>
 */
public class Web3App {

   public static Pair<String, String> generateKeyPair() throws Throwable {
      try (
            PrivateEncKeyMlKem512 privateKey = PrivateEncKeyMlKem512.generate();
            PublicEncKeyMlKem512 publicKey = PublicEncKeyMlKem512.fromPrivateKey(privateKey)) {
         return new Pair<>(
               Hex.toHexString(publicKey.serialize()),
               Hex.toHexString(privateKey.serialize()));
      }
   }

   private static String getEthPrivateKey(Config config) {
      /*
       * if (_ethPrivateKey == null)
       * {
       * _ethPrivateKey = config.EthPrivateKey;
       * if (string.IsNullOrWhiteSpace(_ethPrivateKey))
       * {
       * Console.Write("Enter the ETH private key: ");
       * _ethPrivateKey = ConsoleReadPassword.Read();
       * }
       * _ethPrivateKey = _ethPrivateKey.Trim();
       * if (_ethPrivateKey.Length != 64)
       * throw new InvalidDataException("Invalid ETH private key.");
       * }
       * return _ethPrivateKey;
       */
      return config.EthPrivateKey;
   }

   private static String getInfuraApiKey(Config config) {
      /*
       * if (_infuraApiKey == null)
       * {
       * _infuraApiKey = config.InfuraApiKey;
       * if (string.IsNullOrWhiteSpace(_infuraApiKey))
       * {
       * Console.Write("Enter the Infura API key: ");
       * _infuraApiKey = ConsoleReadPassword.Read();
       * }
       * _infuraApiKey = _infuraApiKey.Trim();
       * }
       * 
       * return _infuraApiKey;
       */
      return config.InfuraApiKey;
   }

   private static Web3j createWeb3(Config config, FhevmConfig fhevmConfig) {
      String rpcUrl = fhevmConfig.getInfuraUrl() + "/" + getInfuraApiKey(config);
      Web3j web3j = Web3j.build(new HttpService(rpcUrl));

      return web3j;
   }

   private static List<String> _kmsSigners;
   private static int _kmsSignersThreshold;

   @SuppressWarnings("rawtypes")
   private static void getKMSSigners(Web3j web3j, Config config, FhevmConfig fhevmConfig) throws Throwable {
      if (_kmsSigners == null) {
         var credentials = Credentials.create(config.EthPrivateKey);

         Function function;
         EthCall response;
         List<Type> output;

         function = new Function(
               "getKmsSigners",
               List.of(),
               List.of(new TypeReference<DynamicArray<Address>>() {
               }));
         response = web3j.ethCall(
               Transaction.createEthCallTransaction(credentials.getAddress(), fhevmConfig.getKmsContractAddress(),
                     FunctionEncoder.encode(function)),
               DefaultBlockParameterName.LATEST)
               .send();
         output = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());

         @SuppressWarnings("unchecked")
         DynamicArray<Address> signerArray = (DynamicArray<Address>) output.get(0);
         _kmsSigners = signerArray.getValue().stream()
               .map(a -> AddressHelper.getChecksumAddress(a.getValue()))
               .toList();

         function = new Function(
               "getThreshold",
               List.of(),
               List.of(new TypeReference<Uint256>() {
               }));
         response = web3j.ethCall(
               Transaction.createEthCallTransaction(credentials.getAddress(), fhevmConfig.getKmsContractAddress(),
                     FunctionEncoder.encode(function)),
               DefaultBlockParameterName.LATEST)
               .send();
         output = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
         _kmsSignersThreshold = ((BigInteger) output.get(0).getValue()).intValue();
      }
   }

   private static List<String> _coprocessorSigners;
   private static int _coprocessorSignersThreshold;

   @SuppressWarnings("rawtypes")
   private static void getCoprocessorSigners(Web3j web3j, Config config, FhevmConfig fhevmConfig) throws Throwable {
      if (_coprocessorSigners == null) {
         var credentials = Credentials.create(config.EthPrivateKey);

         Function function;
         EthCall response;
         List<Type> output;

         function = new Function(
               "getCoprocessorSigners",
               List.of(),
               List.of(new TypeReference<DynamicArray<Address>>() {
               }));
         response = web3j.ethCall(
               Transaction.createEthCallTransaction(credentials.getAddress(),
                     fhevmConfig.getInputVerifierContractAddress(),
                     FunctionEncoder.encode(function)),
               DefaultBlockParameterName.LATEST)
               .send();
         output = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());

         @SuppressWarnings("unchecked")
         DynamicArray<Address> signerArray = (DynamicArray<Address>) output.get(0);
         _coprocessorSigners = signerArray.getValue().stream()
               .map(a -> AddressHelper.getChecksumAddress(a.getValue()))
               .toList();

         function = new Function(
               "getThreshold",
               List.of(),
               List.of(new TypeReference<Uint256>() {
               }));
         response = web3j.ethCall(
               Transaction.createEthCallTransaction(credentials.getAddress(),
                     fhevmConfig.getInputVerifierContractAddress(),
                     FunctionEncoder.encode(function)),
               DefaultBlockParameterName.LATEST)
               .send();
         output = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
         _coprocessorSignersThreshold = ((BigInteger) output.get(0).getValue()).intValue();
      }
   }

   private static FHECounter getFHECounterContract(Web3j web3j, Config config, FhevmConfig fhevmConfig) {
      var credentials = Credentials.create(config.EthPrivateKey);
      // skip validity check for now (fheCounter.isValid())
      return FHECounter.load(config.FHECounterContractAddress, web3j, credentials, new DefaultGasProvider());
   }

   private static String retrieveCurrentFHECounterHandle(FHECounter counterContract) throws Throwable {
      byte[] counterHandleBytes = counterContract.getCount().send();
      return Helpers.to0xHexString(counterHandleBytes);
   }

   public static void decryptFHECounterValue(Web3j web3j, Config config, FhevmConfig fhevmConfig) throws Throwable {
      System.out.println("Retrieving FHECounter contract " + config.FHECounterContractAddress + "...");

      System.out.println("Generating key pair...");

      Pair<String, String> kp = generateKeyPair();
      String localPublicKey = kp.item1();
      String localPrivateKey = kp.item2();

      System.out.println("Creating EIP-712 typed data...");

      var now = LocalDateTime.now(ZoneOffset.UTC);

      String typedDataJson = Eip712.create(
            fhevmConfig,
            localPublicKey,
            new String[] { config.FHECounterContractAddress },
            now /* startTime */,
            365 /* durationDays */);

      System.out.println("Signing EIP-712 typed data...");

      BigInteger ethPrivateKey = Numeric.toBigInt(getEthPrivateKey(config));
      BigInteger ethPublicKey = Sign.publicKeyFromPrivate(ethPrivateKey);
      var ethKeyPair = new ECKeyPair(ethPrivateKey, ethPublicKey);

      Sign.SignatureData signature = Sign.signTypedData(typedDataJson, ethKeyPair);
      byte[] retval = new byte[65];
      System.arraycopy(signature.getR(), 0, retval, 0, 32);
      System.arraycopy(signature.getS(), 0, retval, 32, 32);
      System.arraycopy(signature.getV(), 0, retval, 64, 1);
      String eip712Signature = Numeric.toHexString(retval);

      System.out.println("EIP-712 signature: " + eip712Signature);

      FHECounter contract = getFHECounterContract(web3j, config, fhevmConfig);
      String counterHandle = retrieveCurrentFHECounterHandle(contract);
      System.out.println(
            "Counter handle: " + counterHandle + " (encrypted type: " + HandleHelper.getValueType(counterHandle) + ")");
      getKMSSigners(web3j, config, fhevmConfig);

      System.out.println("Decrypting handle...");

      try (UserDecrypt decrypt = new UserDecrypt(config, fhevmConfig, _kmsSigners)) {
         List<HandleContractPair> handleContractPairs = List.of(
               new HandleContractPair(counterHandle, config.FHECounterContractAddress));

         Map<String, Object> result = decrypt.decrypt(
               web3j,
               handleContractPairs,
               localPrivateKey,
               localPublicKey,
               eip712Signature,
               List.of(config.FHECounterContractAddress),
               config.UserAddress,
               now /* startTime */,
               365/* durationDays */);

         Object value = result.get(counterHandle);

         System.out.println("Success:");

         System.out.println("Counter handle: " + counterHandle + " (encrypted type: "
               + HandleHelper.getValueType(counterHandle) + ")");
         System.out.println("Counter value : " + value + " (Java type: " + value.getClass() + ")");
      }
   }

   public static void addToFHECounter(Web3j web3j, Config config, FhevmConfig fhevmConfig, int value) throws Throwable {
      System.out.println("Retrieiving coprocessor signers...");

      getCoprocessorSigners(web3j, config, fhevmConfig);

      FhevmEncryptedValues encryptedValues;

      try (var fhevmKeys = new FhevmKeys()) {
         System.out.println("Retrieving keys from Zama server...");
         FhevmKeys.Keys keys = fhevmKeys.getOrDownload(fhevmConfig.getRelayerUrl());

         System.out.println("Encrypting input value (" + Math.abs(value) + ")...");

         try (var builder = new EncryptedValuesBuilder(keys.getCompactPublicKeyInfo())) {

            builder.pushU32((int) Math.abs(value));

            String contractAddress = config.FHECounterContractAddress;
            String userAddress = config.UserAddress;

            encryptedValues = FhevmEncrypter.Encrypt(
                  fhevmConfig,
                  builder,
                  keys.getPublicParamsInfo(),
                  _coprocessorSigners,
                  _coprocessorSignersThreshold,
                  contractAddress,
                  userAddress);
         }
      }

      System.out.println("Encrypted input value handle: " + encryptedValues.getHandles().get(0));
      System.out.println("Encrypted input value proof: " + encryptedValues.getInputProof());

      System.out.println("Retrieving FHECounter contract " + config.FHECounterContractAddress + "...");

      FHECounter contract = getFHECounterContract(web3j, config, fhevmConfig);

      String functionName = value >= 0 ? "increment" : "decrement";

      System.out.println("Calling " + functionName + "() function...");

      TransactionReceipt txReceipt;

      byte[] inputEuint32 = Hex.fromHexString(Helpers.remove0xIfAny(encryptedValues.getHandles().get(0)));
      byte[] inputProof = Hex.fromHexString(Helpers.remove0xIfAny(encryptedValues.getInputProof()));
      if (value >= 0) {
         txReceipt = contract.increment(inputEuint32, inputProof).send();
      } else {
         txReceipt = contract.decrement(inputEuint32, inputProof).send();
      }

      System.out.println("Transaction hash: " + txReceipt.getTransactionHash());
      System.out.println("Block number: " + txReceipt.getBlockNumber());
      System.out.println("Gas used: " + txReceipt.getGasUsed());

      String counterHandle = retrieveCurrentFHECounterHandle(contract);
      System.out.println("New FHE Counter handle: " + counterHandle);
   }

   private static void PrintFHECounterHandle(Web3j web3j, Config config, FhevmConfig fhevmConfig) throws Throwable {
      System.out.println("Retrieving FHECounter contract " + config.FHECounterContractAddress + "...");

      FHECounter counterContract = getFHECounterContract(web3j, config, fhevmConfig);
      String counterHandle = retrieveCurrentFHECounterHandle(counterContract);

      System.out.println(
            "Counter handle: " + counterHandle + " (encrypted type: " + HandleHelper.getValueType(counterHandle) + ")");
   }

   private static void silentHttpServiceDebugLogging() {
      Logger httpLogger = (Logger) LoggerFactory.getLogger("org.web3j.protocol.http.HttpService");
      httpLogger.setLevel(Level.ERROR);

      // Logger okhttpLogger = (Logger) LoggerFactory.getLogger("okhttp3");
      // okhttpLogger.setLevel(Level.ERROR);
   }

   private static void printUsage() {
      String usage = """
            Description:
              Simple FHECounter client app on Sepolia

            Usage:
              FHECounterClient [command] [options]

            Options:
              -?, -h, --help  Show help and usage information
              --version       Show version information

            Commands:
              print-counter-handle       Print the FHE counter handle.
              decrypt-counter-value      Decrypt and print FHE counter value.
              increment VALUE            Increment counter.
              decrement VALUE            Decrement counter.
            """;
      // TODO
      // print-public-value-handle Print the public value handle.
      // decrypt-public-value Decrypt and print FHE public value.

      System.out.println(usage);
   }

   public static void main(String[] args) throws Throwable {
      silentHttpServiceDebugLogging();

      if (args.length < 1) {
         printUsage();
         return;
      }

      Config config = new ObjectMapper().readValue(new java.io.File("src/main/java/org/web3j/Config.json"),
            Config.class);
      FhevmConfig fhevmConfig = new FhevmSepoliaConfig();

      String command = args[0].toLowerCase();
      switch (command) {
         case "print-counter-handle": {
            try (Web3j web3j = createWeb3(config, fhevmConfig)) {
               PrintFHECounterHandle(web3j, config, fhevmConfig);
            }
         }
         // case "print-public-value-handle":
         case "decrypt-counter-value": {
            try (Web3j web3j = createWeb3(config, fhevmConfig)) {
               decryptFHECounterValue(web3j, config, fhevmConfig);
            }
            break;
         }
         case "decrement":
         case "increment": {
            if (args.length < 2) {
               System.out.println("Missing value argument.");
               printUsage();
               return;
            }
            int value = Integer.parseInt(args[1]);
            if (value <= 0) {
               System.out.println("Value must be positive for " + command + " command.");
               printUsage();
               return;
            }
            try (Web3j web3j = createWeb3(config, fhevmConfig)) {
               addToFHECounter(web3j, config, fhevmConfig, command.equals("decrement") ? -value : value);
            }
            break;
         }
         // case "decrypt-public-value":
         case "-?":
         case "-h":
         case "--help":
            printUsage();
            return;
         case "--version":
            System.out.println("FHECounterClient version 0.1.0");
            return;
         default:
            System.out.println("Unknown command: " + command);
            printUsage();
            return;
      }
   }
}

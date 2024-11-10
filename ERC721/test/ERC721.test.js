const { web3, artifacts } = require("hardhat");
const {
  expectRevert, // Assertions for transactions that should fail
} = require("@openzeppelin/test-helpers");
const { expect } = require("chai");
//Bringing Out File
const tokenFile = artifacts.require("NewToken");

//Checking Contract Functionalities
contract("-----ERC-721 Token Contract-----", (accounts) => {
  const owner = accounts[0];

  function testAccount(_index) {
    return accounts[_index + 1];
  }
  before(async function () {
    token = await tokenFile.new(owner);
  });

  describe(" ", function () {
    describe("States And Variables", function () {
      describe("", function () {
        it("Checking  Constructor Arguments Owner Variable", async () => {
          //Checking Owner Address
          expect(await token.owner()).equal(owner);
        });
        it("Checking  Constructor Arguments name Variable", async () => {
          //Checking Initial Supply
          expect(await token.name()).to.equal("NewToken");
        });
        it("Checking  Constructor Arguments symbol Variable", async () => {
          //Checking Token Name
          expect(await token.symbol()).equal("NEW");
        });
      });
    });
    describe("", function () {
      describe("Mapping And Functions", function () {
        describe("", function () {
          const user = testAccount(1);
          const tokenId = "1";
          it("Transferring 1 From Owner to User", async () => {
            await token.safeMint(user, tokenId, { from: owner });
            expect(String(await token.ownerOf(tokenId))).equal(String(user));
          });
          it("Should Revert Unbalanced Token Holder", async () => {
            const unBalancedTokenHolder = testAccount(2);
            await expectRevert(
              token.transferFrom(unBalancedTokenHolder, user, tokenId, {
                from: unBalancedTokenHolder,
              }),
              'ERC721InsufficientApproval("0x90F79bf6EB2c4f870365E785982E1f101E93b906", 1)'
            );
          });
          it("Should Revert OwnableUnauthorized For safeMint Function", async () => {
            const tokenId = "2";
            await expectRevert(
              token.safeMint(user, tokenId, { from: user }),
              'OwnableUnauthorizedAccount("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")'
            );
          });
          it("TransferFrom by User", async () => {
            const recipient = testAccount(2);
            await token.transferFrom(user, recipient, tokenId, {
              from: user,
            });
            const tokenOwner = await token.ownerOf(tokenId);
            expect(tokenOwner).equal(recipient);
          });
          it("Checking Approval For User isApprovedForAll that Should returns True", async () => {
            //Mint New Tokens
            const newTokenId = ["2", "3", "4"];
            const recipient = testAccount(2);
            for (let i = 0; i < newTokenId.length; i++) {
              await token.safeMint(owner, newTokenId[i], { from: owner });
            }
            await token.setApprovalForAll(recipient, true, {
              from: owner,
            });
            expect(await token.isApprovedForAll(owner, recipient)).equal(true);
          });
          it("Should Revert Non Token Holder When Try To Burn Token", async () => {
            const tokenId = "1";
            const nonTokenHolder = testAccount(4);
            await expectRevert(
              token.burn(tokenId, { from: nonTokenHolder }),
              'ERC721InsufficientApproval("0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc", 1)'
            );
          });
          it("Should Revert Non Exisistent Token Transferring", async () => {
            const from = testAccount(2);
            const recipient = testAccount(3);
            const tokenId = "1";
            await token.burn(tokenId, { from: from });
            await expectRevert(
              token.safeTransferFrom(from, recipient, tokenId, {
                from: from,
              }),
              "ERC721NonexistentToken(1)"
            );
          });
        });
      });
    });
  });
});

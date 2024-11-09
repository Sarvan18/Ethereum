const { web3, artifacts } = require("hardhat");
const {
  expectRevert // Assertions for transactions that should fail
} = require("@openzeppelin/test-helpers");
const { expect } = require("chai");
//Bringing Out File
const tokenFile = artifacts.require("NewToken");

//Checking Contract Functionalities
contract("-----Token Contract-----", (accounts) => {
  const owner = accounts[0];

  function testAccount(_index) {
    return accounts[_index + 1];
  }
  before(async function () {
    token = await tokenFile.new();
  });

  describe(" ", function () {
    describe("States And Variables", function () {
      describe("", function () {
        it("Checking  Constructor Arguments Owner Variable", async () => {
          //Checking Owner Address
          expect(await token.owner()).equal(owner);
        });
        it("Checking  Constructor Arguments totalSupply Variable", async () => {
          //Checking Initial Supply
          const initiallyMintedValue = web3.utils.toWei("100000", "ether");
          expect(Number(await token.totalSupply())).to.equal(
            Number(initiallyMintedValue)
          );
        });
        it("Checking  Constructor Arguments Name Variable", async () => {
          //Checking Token Name
          const name = "NewToken";
          expect(await token.name()).equal(name);
        });
        it("Checking  Constructor Arguments Symbol Variable", async () => {
          //Checking Token Symbol
          const symbol = "NEW";
          expect(await token.symbol()).equal(symbol);
        });
      });
    });
    describe("", function () {
      describe("Mapping And Functions", function () {
        describe("", function () {
          const user = testAccount(1);
          const amount = web3.utils.toWei("1", "ether");
          it("Transferring 1e18 From Owner to User", async () => {
            const userBalanceBefore = await token.balanceOf(user);
            await token.transfer(user, amount, { from: owner });
            const userBalanceAfter = await token.balanceOf(user);
            expect(Number(userBalanceBefore) + Number(userBalanceAfter)).equal(
              Number(amount)
            );
          });
          it("Should Revert Unbalanced Token Holder", async () => {
            const unBalancedTokenHolder = testAccount(2);
            await expectRevert(
              token.transfer(user, amount, { from: unBalancedTokenHolder }),
              'ERC20InsufficientBalance("0x90F79bf6EB2c4f870365E785982E1f101E93b906", 0, 1000000000000000000)'
            );
          });
          it("Should Revert OwnableUnauthorized For Mint Function", async () => {
            await expectRevert(
              token.mint(user, amount, { from: user }),
              'OwnableUnauthorizedAccount("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")'
            );
          });
          it("Approving And TransferFrom by User", async () => {
            const userBalanceBefore = await token.balanceOf(user);
            await token.approve(user, amount, { from: owner });
            await token.transferFrom(owner, user, amount, { from: user });
            const userBalanceAfter = await token.balanceOf(user);
            expect(Number(userBalanceBefore) + Number(amount)).equal(
              Number(userBalanceAfter)
            );
          });
        });
      });
    });
  });
});

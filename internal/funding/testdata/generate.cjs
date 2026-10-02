const fs=require('node:fs');const path=require('node:path');
const root=path.resolve(process.argv[2] || '');
if (!process.argv[2]) throw Error('Pass the isolated v2 protocol checkout with its local harness and IDL');
const anchor=require(path.join(root,'.tools/harness/node_modules/@coral-xyz/anchor'));
const web3=require(path.join(root,'.tools/harness/node_modules/@solana/web3.js'));
const idl=JSON.parse(fs.readFileSync(path.join(root,'.tools/scarlett-idl.json')));
const coder=new anchor.Program(idl,{connection:{},wallet:{}}).coder;const type=idl.types.find(t=>t.name.toLowerCase()==='quote').name;
const key=n=>new web3.PublicKey(Buffer.alloc(32,n));const program=new web3.PublicKey('9gQqmsmJ36VhQjbUzdgKe9S8rKQXUBWo5dcC1eTy83YM');
const publisher=web3.Keypair.fromSeed(Buffer.alloc(32,7));
const derive=(seed,bytes)=>web3.PublicKey.findProgramAddressSync([Buffer.from(seed),...(bytes?[bytes]:[])],program);
const [config,configBump]=derive('config');const [job,jobBump]=derive('job',key(3).toBuffer());const [escrow,escrowBump]=derive('escrow',job.toBuffer());
const now=1893456000;const quote={version:2,program,config,devnetGenesis:Array.from(key(2).toBuffer()),jobId:Array.from(key(3).toBuffer()),buyer:key(4),supplier:key(5),serviceId:Array.from(Buffer.from('CODEX-LOCAL-0001')),inputCommitment:Array.from(key(9).toBuffer()),maxWorkUnits:new anchor.BN(150),price:new anchor.BN(1000000),quoteExpiry:new anchor.BN(now+25),jobDeadline:new anchor.BN(now+60)};
const raw=coder.types.encode(type.toLowerCase(),quote);if(raw.length!==273)throw Error('quote size');
const msg=Buffer.concat([Buffer.from('scarlett/quote/v2'),raw]);const ix=web3.Ed25519Program.createInstructionWithPrivateKey({privateKey:publisher.secretKey,message:msg});const offset=ix.data.readUInt16LE(2);const sig=ix.data.subarray(offset,offset+64);
const output={source:'Synthetic Anchor 0.31.1 BorshCoder and Solana web3.js fixture, no chain or payment',now,program:program.toBase58(),publisher:publisher.publicKey.toBase58(),config:config.toBase58(),job:job.toBase58(),escrow:escrow.toBase58(),configBump,jobBump,escrowBump,quoteBase64:raw.toString('base64'),signatureBase64:sig.toString('base64')};

(async()=>{
const spl=require(path.join(root,'.tools/harness/node_modules/@solana/spl-token'));
const none={id:Array(16).fill(0),kind:{codex:{}},maxWorkUnits:new anchor.BN(0)};
const cfg={publisher:publisher.publicKey,usdcMint:key(11),treasury:key(12),devnetGenesis:quote.devnetGenesis,serviceCount:2,services:[{id:quote.serviceId,kind:{codex:{}},maxWorkUnits:new anchor.BN(150)},{id:Array.from(Buffer.from('XREAD-LOCAL-0001')),kind:{xRead:{}},maxWorkUnits:new anchor.BN(10)},...Array.from({length:6},()=>none)],bump:configBump};
const storedJob={id:quote.jobId,buyer:quote.buyer,supplier:quote.supplier,serviceId:quote.serviceId,kind:{codex:{}},inputCommitment:quote.inputCommitment,resultCommitment:Array(32).fill(0),maxWorkUnits:quote.maxWorkUnits,workUnits:new anchor.BN(0),price:quote.price,deadline:quote.jobDeadline,state:{funded:{}}};
const escrowData=Buffer.alloc(spl.AccountLayout.span);spl.AccountLayout.encode({mint:key(11),owner:config,amount:1000000n,delegateOption:0,delegate:key(0),state:1,isNativeOption:0,isNative:0n,delegatedAmount:0n,closeAuthorityOption:0,closeAuthority:key(0)},escrowData);
output.configBase64=(await coder.accounts.encode('config',cfg)).toString('base64');output.jobBase64=(await coder.accounts.encode('job',storedJob)).toString('base64');output.escrowBase64=escrowData.toString('base64');
const out=path.join(__dirname,'anchor-v2.json');fs.mkdirSync(path.dirname(out),{recursive:true});fs.writeFileSync(out,JSON.stringify(output,null,2)+'\n');console.log('Synthetic Anchor quote, accounts, SPL escrow and PDA vectors generated without RPC or payment');
})().catch(e=>{console.error(e.message);process.exitCode=1});

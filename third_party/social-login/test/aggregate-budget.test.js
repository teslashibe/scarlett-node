import assert from 'node:assert/strict';
import test from 'node:test';
import {LoginBudget} from '../src/runtime/login-budget.js';
test('continuation restores aggregate counters and forbids fresh browser/password work',async()=>{
 const first=new LoginBudget({max_browser_attempts:2,max_credential_attempts:1,max_solver_attempts:0});
 first.use('browser');first.use('credential');const state=first.snapshot();await first.dispose();
 const next=new LoginBudget({max_browser_attempts:0,max_credential_attempts:0,max_solver_attempts:0});
 try {next.restore(state);assert.equal(next.deadline,state.deadline);assert.deepEqual(next.attempts,state.attempts);assert.throws(()=>next.use('browser'),e=>e.code==='attempts_exhausted');assert.throws(()=>next.use('credential'),e=>e.code==='attempts_exhausted');}finally{await next.dispose();}
});

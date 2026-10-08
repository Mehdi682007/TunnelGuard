import threading
import unittest
from unittest.mock import patch
import tunnel_manager as manager

class ForwardJobTests(unittest.TestCase):
    def test_restart_does_not_block_status_and_replacement_reaches_commit(self):
        entered,release=threading.Event(),threading.Event()
        def commit(cfg):
            entered.set()
            if not release.wait(3): raise RuntimeError('test timeout')
        data=dict(name='xui-4748',listen_host='0.0.0.0',listen_port=4748,target_host='127.0.0.1',target_port=4748,replace=True)
        threads=[]
        real_thread=threading.Thread
        def thread(**kwargs):
            t=real_thread(**kwargs);threads.append(t);return t
        with patch.object(manager,'STATE',{'links':{}}), patch.object(manager,'save'), patch.object(manager.manage,'load_config',return_value={}), patch.object(manager.manage,'add_forward',return_value={'tcp_forwards':[{'name':'xui-4748'}]}) as add, patch.object(manager.manage,'save_managed',side_effect=commit), patch.object(manager.threading,'Thread',side_effect=thread):
            result=manager.dispatch({'op':'forward','data':data})
            try:
                self.assertEqual(result['status'],'pending')
                self.assertTrue(entered.wait(1))
                self.assertEqual(manager.dispatch({'op':'status'})['forward_result'],'pending')
                with self.assertRaises(ValueError): manager.dispatch({'op':'forward','data':data})
                self.assertTrue(add.call_args.args[-1])
            finally:
                release.set()
                for t in threads:t.join(2)
            self.assertEqual(manager.status()['forward_result'],'applied')

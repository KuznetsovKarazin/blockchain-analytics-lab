"""Exact-ID alignment and explicitly selected original-column contract."""
import csv
from pathlib import Path
import sys
import tempfile
import unittest

import numpy as np

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from elliptic_data import load_tabular, FILES, DIRECT18


class LoaderTests(unittest.TestCase):
    def fixture(self, path):
        rows=[[22,1,*range(165)],[11,2,*range(1000,1165)],[33,3,*range(2000,2165)]]
        with (path/FILES[0]).open('w',newline='') as handle:csv.writer(handle).writerows(rows)
        self.classes(path,[(11,'1'),(33,'unknown'),(22,'2')])
        return rows

    def classes(self,path,rows):
        with (path/FILES[1]).open('w',newline='') as handle:
            writer=csv.writer(handle);writer.writerow(['txId','class']);writer.writerows(rows)

    def test_ids_align_labels_after_class_row_shuffle(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root)
            data=load_tabular(root,verify_hashes=False)
            np.testing.assert_array_equal(data.tx_ids,[22,11,33])
            np.testing.assert_array_equal(data.y,[0,1,-1])
            self.assertEqual(data.X.shape,(3,18))
            self.assertEqual(data.feature_columns,DIRECT18)
            self.assertEqual(data.X[0,0],0)

    def test_requested_feature_column_order_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root)
            data=load_tabular(root,feature_columns=[22,2,3],verify_hashes=False)
            np.testing.assert_array_equal(data.X[0],[20,0,1])

    def test_missing_id_not_coerced_to_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root);self.classes(root,[(11,'1'),(22,'2')])
            with self.assertRaisesRegex(ValueError,'different txId'):
                load_tabular(root,verify_hashes=False)

    def test_invalid_label_not_coerced_to_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root);self.classes(root,[(11,'1'),(33,'unrecognised'),(22,'2')])
            with self.assertRaisesRegex(ValueError,'unrecognized'):
                load_tabular(root,verify_hashes=False)

    def test_duplicate_class_ids_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root);self.classes(root,[(11,'1'),(11,'2'),(33,'unknown'),(22,'2')])
            with self.assertRaisesRegex(ValueError,'unique txId'):
                load_tabular(root,verify_hashes=False)


if __name__=='__main__':unittest.main()

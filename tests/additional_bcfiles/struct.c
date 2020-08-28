struct ThreeInts {
  int el0;
  int el1;
  int el2;
};

void called(struct ThreeInts* ti) {
  ti->el2 = ti->el0;
}

int caller(int x) {
  struct ThreeInts ti = { 0 };
  ti.el0 = x;
  called(&ti);
  return ti.el2;
}

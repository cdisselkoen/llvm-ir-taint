struct TwoInts {
  int el0;
  int el1;
};

void called(struct TwoInts* ti, int val) {
  ti->el1 = val;
}

int caller(int x) {
  struct TwoInts ti = { 0 };
  called(&ti, x);
  return ti.el1;
}

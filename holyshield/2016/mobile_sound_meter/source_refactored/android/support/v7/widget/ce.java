package android.support.v7.widget;

class ce implements Runnable {
    final /* synthetic */ cd f1442a;

    private ce(cd cdVar) {
        this.f1442a = cdVar;
    }

    public void run() {
        this.f1442a.f987d.getParent().requestDisallowInterceptTouchEvent(true);
    }
}

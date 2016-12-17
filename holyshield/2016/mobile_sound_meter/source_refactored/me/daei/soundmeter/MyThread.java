package me.daei.soundmeter;

/* renamed from: me.daei.soundmeter.g */
class MyThread implements Runnable {
    final /* synthetic */ SecondActivity soundActivity;

    MyThread(SecondActivity secondActivity) {
        this.soundActivity = secondActivity;
    }

    public void run() {
        while (this.soundActivity.created) {
            try {
                if (this.soundActivity.recording) {
                    this.soundActivity.soundAmplitude = this.soundActivity.audioManager.getMaxAmplitude();
                    if (this.soundActivity.soundAmplitude > 0.0f && this.soundActivity.soundAmplitude < 1000000.0f) {
                        StaticHolder.update(20.0f * ((float) Math.log10((double) this.soundActivity.soundAmplitude)));
                        this.soundActivity.soundDiskView.updateView();
                    }
                }
                Thread.sleep(100);
            } catch (InterruptedException e) {
                e.printStackTrace();
                this.soundActivity.recording = false;
            }
        }
    }
}

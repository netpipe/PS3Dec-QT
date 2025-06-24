#include <QApplication>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QFileDialog>
#include <QTextEdit>
#include <QLabel>
#include <QLineEdit>
#include <QFile>
#include <QDataStream>
#include <QByteArray>
#include <QMessageBox>
#include <openssl/evp.h>

// Simplified SELF header structures
struct SelfHeader {
    quint32 magic;
    quint16 version;
    quint16 segCount;
    quint64 segmentInfoOffset;
};

struct SegmentInfo {
    quint64 offset;
    quint64 size;
    quint64 decryptedSize;
    quint64 flags;
};

class PS3DecGUI : public QWidget {
    Q_OBJECT
public:
    PS3DecGUI(QWidget *parent=nullptr): QWidget(parent){
        auto *layout = new QVBoxLayout(this);
        auto *fileLayout = new QHBoxLayout;
        auto *loadBtn = new QPushButton("Load .self/.sprx");
        keyInput = new QLineEdit();
        keyInput->setPlaceholderText("Enter AES key (hex)");
        fileLayout->addWidget(loadBtn);
        fileLayout->addWidget(keyInput);
        auto *decryptBtn = new QPushButton("Decrypt");
        status = new QLabel("Status: waiting...");
        logOut = new QTextEdit(); logOut->setReadOnly(true);
        layout->addLayout(fileLayout);
        layout->addWidget(decryptBtn);
        layout->addWidget(status);
        layout->addWidget(logOut);

        connect(loadBtn,&QPushButton::clicked,this,&PS3DecGUI::onLoad);
        connect(decryptBtn,&QPushButton::clicked,this,&PS3DecGUI::onDecrypt);
    }

private slots:
    void onLoad(){
        file = QFileDialog::getOpenFileName(this,"Select SELF File","","SELF/SPRX Files (*.self *.sprx)");
        if(!file.isEmpty()){
            status->setText("Loaded: " + file);
            logOut->append("File: " + file);
        }
    }

    void onDecrypt(){
        if(file.isEmpty()){ QMessageBox::warning(this,"Error","No file loaded"); return; }
        QString keyHex = keyInput->text().trimmed();
        if(keyHex.length() != 32){ QMessageBox::warning(this,"Error","AES key must be 128-bit (32 hex digits)"); return; }

        QByteArray key = QByteArray::fromHex(keyHex.toLatin1());
        QFile f(file);
        if(!f.open(QIODevice::ReadOnly)){ QMessageBox::critical(this,"Error","Cannot open file."); return; }
        QByteArray blob = f.readAll();
        f.close();

        QDataStream ds(blob);
        SelfHeader hdr;
        ds.setByteOrder(QDataStream::LittleEndian);
        ds >> hdr.magic >> hdr.version >> hdr.segCount >> hdr.segmentInfoOffset;

        if(hdr.magic != 0x454C4653 /*"SELF"*/){
            QMessageBox::critical(this,"Error","Not a valid SELF/SPRX.");
            return;
        }

        QList<SegmentInfo> segs;
        ds.device()->seek(hdr.segmentInfoOffset);
        for(int i=0;i<hdr.segCount;i++){
            SegmentInfo si;
            ds >> si.offset >> si.size >> si.decryptedSize >> si.flags;
            segs.append(si);
            logOut->append(QString("Seg %1: off=%2 size=%3 flags=%4").arg(i).arg(si.offset).arg(si.size).arg(si.flags));
        }

        // Setup OpenSSL
        QByteArray out(blob); // reuse
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if(!ctx){ QMessageBox::critical(this,"Error","Failed to init OpenSSL."); return; }

        for(int i=0;i<segs.size();i++){
            const auto &si=segs[i];
            if(!(si.flags & 1)) continue; // only encrypted segments
            QByteArray iv = QByteArray(16, '\0');
            // IV derivation: simple here; adapt from keyset logic if needed
            memcpy(iv.data(), blob.constData() + si.offset, 16);

            if(EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr,
                                  reinterpret_cast<const unsigned char*>(key.data()),
                                  reinterpret_cast<const unsigned char*>(iv.data())) !=1){
                QMessageBox::critical(this,"Error","DecryptInit failed"); EVP_CIPHER_CTX_free(ctx); return;
            }

            int outl=0, outlen_final=0;
            EVP_DecryptUpdate(ctx,
                        reinterpret_cast<unsigned char*>(out.data()+si.offset), &outl,
                        reinterpret_cast<const unsigned char*>(blob.constData()+si.offset),
                        si.size);
            EVP_DecryptFinal_ex(ctx,
                        reinterpret_cast<unsigned char*>(out.data()+si.offset)+outl, &outlen_final);
            logOut->append(QString("Seg %1 decrypted (%2 bytes)").arg(i).arg(outl+outlen_final));
        }
        EVP_CIPHER_CTX_free(ctx);

        QString of = file + ".dec";
        QFile fout(of);
        if(fout.open(QIODevice::WriteOnly)){
            fout.write(out);
            fout.close();
            status->setText("Decrypted → " + of);
            logOut->append("Written to " + of);
        } else logOut->append("Failed to write output.");
    }

private:
    QString file;
    QLineEdit *keyInput;
    QLabel *status;
    QTextEdit *logOut;
};



int main(int argc, char *argv[]){
    QApplication app(argc,argv);
    PS3DecGUI w;
    w.setWindowTitle("PS3 SELF Decryptor (Qt + OpenSSL)");
    w.resize(600, 450);
    w.show();
    return app.exec();
}
#include "main.moc"

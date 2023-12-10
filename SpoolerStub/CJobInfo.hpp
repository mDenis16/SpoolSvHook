class CJobInfo
{
public:
    void *buff = nullptr;
    unsigned long buffSize = 0;
    void *hPrinter = nullptr;
    int JobId = 0;
    int Level = 0;


    CJobInfo(void *_hPrinter, int _JobId, int _Level);


    template <typename T>
    T* CastData(){
        return (T*)(buff);
    }

    
    ~CJobInfo();
};
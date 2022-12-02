#pragma once

template<class T>
class Singleton {
public:

    Singleton(const Singleton &other) = delete;
    Singleton& operator=(const Singleton &other) = delete;

    static T& instance() {
        static T _instance;
        return _instance;
    }

protected:
    Singleton() = default;
    ~Singleton() = default;

};

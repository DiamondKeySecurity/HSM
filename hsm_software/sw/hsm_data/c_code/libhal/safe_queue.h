// By ChewOnThis_Trident on StackOverflow
// You agree that any and all content, including without limitation any and all text, graphics,
// logos, tools, photographs, images, illustrations, software or source code, audio and video,
// animations, and product feedback (collectively, “Content”) that you provide to the public
// Network (collectively, “Subscriber Content”), is perpetually and irrevocably licensed to
// Stack Overflow on a worldwide, royalty-free, non-exclusive basis pursuant to Creative Commons
// licensing terms (CC-BY-SA), and you grant Stack Overflow the perpetual and irrevocable right
// and license to access, use, process, copy, distribute, export, display and to commercially
// exploit such Subscriber Content, even if such Subscriber Content has been contributed and
// subsequently removed by you as reasonably necessary to, for example (without limitation):

// - Provide, maintain, and update the public Network
// - Process lawful requests from law enforcement agencies and government agencies
// - Prevent and address security incidents and data security features, support features, and to
//   provide technical assistance as it may be required
// - Aggregate data to provide product optimization

// This means that you cannot revoke permission for Stack Overflow to publish, distribute, store
// and use such content and to allow others to have derivative rights to publish, distribute,
// store and use such content. The CC-BY-SA Creative Commons license terms are explained in
// further detail by Creative Commons, but you should be aware that all Public Content you
// contribute is available for public copy and redistribution, and all such Public Content must
// have appropriate attribution.

// As stated above, by agreeing to these Public Network Terms you also agree to be bound by the
// terms and conditions of the Acceptable Use Policy incorporated herein, and hereby acknowledge
// and agree that any and all Public Content you provide to the public Network is governed by the
// Acceptable Use Policy.


#ifndef SAFE_QUEUE
#define SAFE_QUEUE

#include <queue>
#include <mutex>
#include <condition_variable>

#include <iostream>

// A threadsafe-queue.
template <class T>
class SafeQueue
{
public:
  SafeQueue(void)
    : q()
    , m()
    , c()
  {}

  ~SafeQueue(void)
  {
    std::cout << "deleting SafeQueue" << std::endl;
  }

  // Add an element to the queue.
  void enqueue(T &&t)
  {
    std::lock_guard<std::mutex> lock(m);
    q.push(std::move(t));
    c.notify_one();
  }

  // Get the "front"-element.
  // If the queue is empty, wait till a element is avaiable.
  T dequeue(void)
  {
    std::unique_lock<std::mutex> lock(m);
    while(q.empty())
    {
      // release lock as long as the wait and reaquire it afterwards.
      c.wait(lock);
    }
    T val = std::move(q.front());
    q.pop();
    return val;
  }

  // instead of returning the element for an std::move, do the move
  // and return via reference argument
  void dequeue(T &result)
  {
    result = std::move(dequeue());
  }

private:
  std::queue<T> q;
  mutable std::mutex m;
  std::condition_variable c;
};
#endif